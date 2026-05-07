import json
import logging
import os
from typing import ClassVar

from django.conf import settings
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import redirect, render
from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from rest_framework import serializers, status, throttling
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.response import Response
from rest_framework.views import APIView

from .data_files import MtimeReloadingJson
from .serializers import ProvideCollateralSerializer
from .signature import witness_tx_cbor

logger = logging.getLogger("api")


_known_hosts: MtimeReloadingJson | None = None


def _known_hosts_loader() -> MtimeReloadingJson:
    """Return the singleton loader, rebuilding if settings.KNOWN_HOSTS_PATH
    has changed (so override_settings works in tests)."""
    global _known_hosts
    path = settings.KNOWN_HOSTS_PATH
    if _known_hosts is None or _known_hosts.path != path:
        _known_hosts = MtimeReloadingJson(path, default={})
    return _known_hosts


def _known_hosts_path() -> str:
    """Used by /healthz to report whether the known-hosts file is on disk."""
    return _known_hosts_loader().path


def _load_known_hosts() -> dict:
    """Return the parsed known-hosts registry, re-reading from disk if the
    file has been updated since the last call."""
    return _known_hosts_loader().get()


def _client_ip(request) -> str | None:
    """Best-effort client IP extraction.

    Only honors X-Forwarded-For when the immediate peer (Django's
    REMOTE_ADDR) is in ``settings.TRUSTED_PROXY_IPS``. Otherwise returns
    REMOTE_ADDR directly — a client connecting to gunicorn without the
    proxy in front can't spoof their source IP and bypass the per-IP
    throttle just by setting an X-Forwarded-For header.
    """
    remote = request.META.get("REMOTE_ADDR")
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff and remote in settings.TRUSTED_PROXY_IPS:
        return xff.split(",")[0].strip()
    return remote


class ProvideCollateralThrottle(throttling.AnonRateThrottle):
    # The real bottleneck is the Koios evaluation call, not us. Generous
    # for legit clients (one tx per second), tight enough that a single
    # bad actor can't exhaust an upstream rate limit on their own.
    rate = settings.COLLATERAL_THROTTLE_RATE


@extend_schema_view(
    post=extend_schema(
        operation_id="provide_collateral",
        summary="Sign a transaction that uses this provider's collateral",
        description=(
            "Validate the submitted Cardano transaction CBOR against the "
            "collateral-usage contract and, if it passes, return a vkey "
            "witness for it. Validation includes: collateral UTxO matches "
            "the configured one for this network, the provider PKH appears "
            "in required signers, the collateral is not in inputs, the "
            "is_valid flag is true, and Koios `evaluateTransaction` accepts "
            "the tx. Rate limited per IP."
        ),
        parameters=[
            OpenApiParameter(
                name="environment",
                location=OpenApiParameter.PATH,
                description="One of the configured networks (e.g. `preprod`, `mainnet`).",
                required=True,
                type=str,
            ),
        ],
        request=ProvideCollateralSerializer,
        responses={
            200: OpenApiResponse(
                response=inline_serializer(
                    name="WitnessResponse",
                    fields={"witness": serializers.CharField()},
                ),
                description="Witness CBOR (hex). Decoded shape: `[0, [pubkey, signature]]`.",
            ),
            400: OpenApiResponse(description="Validation error — invalid environment, invalid CBOR, or tx fails the collateral-usage rules."),
            429: OpenApiResponse(description="Rate limit exceeded."),
            503: OpenApiResponse(description="Validation upstream (Koios) is unavailable; try again later."),
        },
        examples=[
            OpenApiExample(
                "Sample request",
                value={"tx": "84a900d901028182582000...f5f6"},
                request_only=True,
            ),
            OpenApiExample(
                "Sample success",
                value={"witness": "8200825820...5840..."},
                response_only=True,
            ),
        ],
    ),
)
class ProvideCollateralView(APIView):
    throttle_classes: ClassVar[list] = [ProvideCollateralThrottle]

    def post(self, request, environment):
        ip_address = _client_ip(request)
        logger.debug("Request received: ip=%s env=%s", ip_address, environment)

        env_settings = settings.ENVIRONMENTS.get(environment)
        if not env_settings:
            logger.warning("Invalid environment: ip=%s env=%s", ip_address, environment)
            return Response(
                {"detail": "Invalid Environment"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = ProvideCollateralSerializer(
            data=request.data,
            context={
                "environment": environment,
                "env_settings": env_settings,
                "ip_address": ip_address,
                "networks": list(settings.ENVIRONMENTS.keys()),
            },
        )
        # raise_exception=True lets the custom DRF exception handler
        # normalize the response shape to {"detail": "..."} consistently
        # with every other 4xx/5xx the API can produce. The validator
        # already logged the specific reason at WARNING level.
        serializer.is_valid(raise_exception=True)
        tx_cbor = serializer.validated_data["tx"]
        witness_cbor = witness_tx_cbor(tx_cbor, settings.SKEY_PATH, settings.VKEY_PATH)
        logger.info("Witnessed tx: ip=%s env=%s", ip_address, environment)
        return Response({"witness": witness_cbor}, status=status.HTTP_200_OK)


@extend_schema(
    operation_id="healthz",
    summary="Liveness/readiness check",
    description=(
        "Returns 200 if the service is configured well enough to serve "
        "signing requests (signing keys readable, known_hosts.json present). "
        "Returns 503 with a list of problems otherwise. Suitable for "
        "container/load-balancer health probes; not rate limited."
    ),
    responses={
        200: OpenApiResponse(
            response=inline_serializer(
                name="HealthOk",
                fields={
                    "status": serializers.CharField(),
                    "version": serializers.CharField(),
                },
            ),
            description="Service ready.",
        ),
        503: OpenApiResponse(
            response=inline_serializer(
                name="HealthError",
                fields={
                    "status": serializers.CharField(),
                    "problems": serializers.ListField(child=serializers.CharField()),
                },
            ),
            description="Service has critical config problems.",
        ),
    },
)
@api_view(["GET"])
@throttle_classes([])
def healthz_view(request):
    problems = []
    for label, path in (("skey", settings.SKEY_PATH), ("vkey", settings.VKEY_PATH)):
        if not os.path.exists(path):
            problems.append(f"{label} missing at {path}")
        elif not os.access(path, os.R_OK):
            problems.append(f"{label} not readable at {path}")
    if not os.path.exists(_known_hosts_path()):
        problems.append(f"known_hosts missing at {_known_hosts_path()}")

    if problems:
        return Response(
            {"status": "error", "problems": problems},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return Response(
        {"status": "ok", "version": settings.SPECTACULAR_SETTINGS["VERSION"]},
        status=status.HTTP_200_OK,
    )


def metrics_view(request):
    """Prometheus exposition endpoint.

    Off by default (METRICS_ENABLED=False) — when off the path returns 404
    and isn't documented in the OpenAPI schema, so a casual scraper has no
    indication the service exposes metrics at all. When on, restricted to
    METRICS_ALLOW_IPS (defaults to localhost only), so a publicly-exposed
    deployment doesn't accidentally serve cluster-internal observability
    data to the world.
    """
    if not settings.METRICS_ENABLED:
        return HttpResponseNotFound()
    client_ip = _client_ip(request)
    if client_ip not in settings.METRICS_ALLOW_IPS:
        logger.warning("Rejected /metrics from non-allowed IP: %s", client_ip)
        return HttpResponse(status=403)
    return HttpResponse(generate_latest(), content_type=CONTENT_TYPE_LATEST)


def landing_page(request):
    """Render the public landing page. Shows the provider's PKH so a user
    can confirm they're talking to the right provider, plus the network
    config from known.hosts.json keyed by that PKH."""
    hosts = _load_known_hosts()
    networks = hosts.get(settings.PKH, "Public Key Hash Not Found In Known Hosts")
    return render(
        request,
        "api/landing.html",
        {"pkh": settings.PKH, "networks_json": json.dumps(networks, indent=4)},
    )


def known_hosts_view(request):
    """Return the full known-hosts registry as JSON. Returns ``{}`` if the
    file is missing — that's the same response shape as an empty registry,
    so consumers don't have to handle two cases."""
    return JsonResponse(_load_known_hosts())


def custom_page_not_found(request, exception):
    return redirect("/")


def custom_disallowed_host_handler(request, exception):
    # request.get_host() can itself raise DisallowedHost; pull the raw
    # header instead so we always log something useful.
    raw = request.META.get("HTTP_HOST", "<missing>")
    logger.warning("DisallowedHost: %s", raw)
    return HttpResponseBadRequest("Invalid Host Header")
