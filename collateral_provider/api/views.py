import json
import logging
import os
from functools import lru_cache
from typing import ClassVar

from django.conf import settings
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from rest_framework import serializers, status, throttling
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import ProvideCollateralSerializer
from .signature import witness_tx_cbor

logger = logging.getLogger("api")


def _known_hosts_path() -> str:
    return os.path.join(os.path.dirname(settings.BASE_DIR), "known.hosts.json")


@lru_cache(maxsize=1)
def _load_known_hosts() -> dict:
    """Load and cache known.hosts.json. The file is part of the deploy
    bundle; it doesn't change at runtime, so reading it once per process
    is enough."""
    with open(_known_hosts_path()) as f:
        return json.load(f)


def _client_ip(request) -> str | None:
    """Best-effort client IP extraction. Trusts X-Forwarded-For from the
    reverse proxy (production deployment assumption — see README)."""
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


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
                value={"tx_body": "84a900d901028182582000...f5f6"},
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
        if not serializer.is_valid():
            # Validator already logged the specific reason at WARNING level.
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        tx_body_cbor = serializer.validated_data["tx_body"]
        witness_cbor = witness_tx_cbor(tx_body_cbor, settings.SKEY_PATH, settings.VKEY_PATH)
        logger.info("Witnessed tx: ip=%s env=%s", ip_address, environment)
        return Response({"witness": witness_cbor}, status=status.HTTP_200_OK)


def landing_page(request):
    """Render the public landing page. Shows the provider's PKH so a user
    can confirm they're talking to the right provider, plus the network
    config from known.hosts.json keyed by that PKH."""
    try:
        hosts = _load_known_hosts()
    except FileNotFoundError:
        hosts = {}
    networks = hosts.get(settings.PKH, "Public Key Hash Not Found In Known Hosts")
    return render(
        request,
        "api/landing.html",
        {"pkh": settings.PKH, "networks_json": json.dumps(networks, indent=4)},
    )


def known_hosts_view(request):
    """Return the full known-hosts registry as JSON."""
    try:
        return JsonResponse(_load_known_hosts())
    except FileNotFoundError:
        return JsonResponse({"detail": "Known Hosts File Not Found"}, status=404)


def custom_page_not_found(request, exception):
    return redirect("/")


def custom_disallowed_host_handler(request, exception):
    # request.get_host() can itself raise DisallowedHost; pull the raw
    # header instead so we always log something useful.
    raw = request.META.get("HTTP_HOST", "<missing>")
    logger.warning("DisallowedHost: %s", raw)
    return HttpResponseBadRequest("Invalid Host Header")
