import ipaddress
import logging
import time
from functools import lru_cache
from typing import ClassVar

from django.conf import settings
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET
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
from .health import readiness_problems
from .known_hosts import validate_known_hosts_registry
from .serializers import ProvideCollateralSerializer
from .services.collateral import issue_witness

logger = logging.getLogger("api")


_known_hosts: MtimeReloadingJson | None = None


def _known_hosts_loader() -> MtimeReloadingJson:
    """Return the singleton loader, rebuilding if settings.KNOWN_HOSTS_PATH
    has changed (so override_settings works in tests)."""
    global _known_hosts
    path = settings.KNOWN_HOSTS_PATH
    if _known_hosts is None or _known_hosts.path != path:
        _known_hosts = MtimeReloadingJson(
            path,
            default={},
            validator=validate_known_hosts_registry,
        )
    return _known_hosts


def _load_known_hosts() -> dict:
    """Return the parsed known-hosts registry, re-reading from disk if the
    file has been updated since the last call."""
    return _known_hosts_loader().get()


@lru_cache(maxsize=1)
def _trusted_proxy_networks(entries: tuple[str, ...]) -> tuple[ipaddress._BaseNetwork, ...]:
    """Parse TRUSTED_PROXY_IPS once into ip_network objects so the per-request
    membership check is cheap. Bare IPs become single-host networks; CIDR
    strings (e.g. ``10.0.0.0/8``) become the corresponding network. Invalid
    entries are dropped with a warning rather than failing the request.

    Container-platform deploys (DigitalOcean App Platform, Fly, Render, ...)
    can't pin a single LB IP, but the container's REMOTE_ADDR is always
    inside the platform's private network — listing the relevant private
    CIDRs lets the throttle key off real client IPs again.
    """
    nets = []
    for entry in entries:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid TRUSTED_PROXY_IPS entry: %r", entry)
    return tuple(nets)


def _is_trusted_proxy(remote: str | None) -> bool:
    if not remote:
        return False
    try:
        peer = ipaddress.ip_address(remote)
    except ValueError:
        return False
    networks = _trusted_proxy_networks(tuple(settings.TRUSTED_PROXY_IPS))
    return any(peer in net for net in networks)


def _parse_ip(value: str | None):
    """Return a validated IP address, or ``None`` for malformed input.

    Forwarding headers are untrusted text even when they arrive through a
    trusted proxy.  Keeping parsing in one place ensures we never use an
    arbitrary header value as a throttle key, ban-list identity, or log
    field.  Scoped IPv6 addresses are intentionally rejected: zone IDs are
    meaningful only on the sender's host and are not valid client identities
    across an HTTP proxy boundary.
    """
    if not value or "%" in value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _client_ip(request) -> str | None:
    """Best-effort client IP extraction.

    Only honors X-Forwarded-For when the immediate peer (Django's
    REMOTE_ADDR) is in ``settings.TRUSTED_PROXY_IPS``. When it is, walk the
    forwarded chain from right to left, skip known proxy hops, and use the
    first untrusted address as the client. This is important for the common
    ``$proxy_add_x_forwarded_for`` configuration: a caller can prefix a fake
    leftmost value, but the proxy-appended real address remains the rightmost
    untrusted hop.

    Otherwise returns validated REMOTE_ADDR directly — a client connecting
    to gunicorn without the proxy in front can't spoof their source IP and
    bypass the per-IP throttle just by setting an X-Forwarded-For header.

    Entries in TRUSTED_PROXY_IPS may be bare IPs (``127.0.0.1``) or CIDR
    blocks (``10.0.0.0/8``). The latter is needed on container platforms
    that don't pin a single load-balancer IP.
    """
    remote = request.META.get("REMOTE_ADDR")
    peer = _parse_ip(remote)
    if peer is None:
        return None

    peer_text = str(peer)
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if not xff or not _is_trusted_proxy(peer_text):
        return peer_text

    for raw_hop in reversed(xff.split(",")):
        hop = _parse_ip(raw_hop)
        if hop is None:
            # Fail closed on a malformed hop. Treat the immediate peer as
            # the identity rather than looking farther left at values the
            # caller may have supplied.
            return peer_text
        hop_text = str(hop)
        if not _is_trusted_proxy(hop_text):
            return hop_text

    # Every supplied hop claims to be a trusted proxy, so the header never
    # established a client address. Do not fall back to its leftmost value.
    return peer_text


class ProvideCollateralThrottle(throttling.AnonRateThrottle):
    # The real bottleneck is the Koios evaluation call, not us. Generous
    # for legit clients (one tx per second), tight enough that a single
    # bad actor can't exhaust an upstream rate limit on their own.
    rate = settings.COLLATERAL_THROTTLE_RATE

    def get_ident(self, request) -> str | None:
        """Use the same trusted-proxy-aware identity as bans and metrics ACLs.

        DRF's default implementation consumes ``X-Forwarded-For`` according
        to its global ``NUM_PROXIES`` setting.  That is a separate trust model
        from this service's ``TRUSTED_PROXY_IPS`` allowlist and, with DRF's
        defaults, lets a directly-connected client forge a new throttle key
        merely by changing the header.  Keeping this override next to
        ``_client_ip`` makes the security boundary explicit and ensures bans,
        metrics authorization, and throttling agree about the caller.
        """
        return _client_ip(request)


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
            "is_valid flag is true, the script-data hash binds the submitted "
            "redeemers/datums, committed execution units cover the evaluated "
            "budgets, and Koios `evaluateTransaction` accepts the tx. Rate "
            "limited per IP."
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
            413: OpenApiResponse(description="JSON request body exceeds the configured pre-parser byte limit."),
            415: OpenApiResponse(description="Unsupported media type — body must be application/json."),
            429: OpenApiResponse(description="Rate limit exceeded."),
            503: OpenApiResponse(description="Validation upstream or local signing identity is unavailable; try again later."),
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
        logger.debug("Collateral request received: env=%s", environment)

        env_settings = settings.ENVIRONMENTS.get(environment)
        if not env_settings:
            logger.warning("Invalid collateral environment: env=%s", environment)
            return Response(
                {"detail": "Invalid Environment"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = ProvideCollateralSerializer(data=request.data)
        # raise_exception=True lets the custom DRF exception handler
        # normalize the response shape to {"detail": "..."} consistently
        # with every other 4xx/5xx the API can produce. Validators inside
        # the service log their own warning-level reasons.
        serializer.is_valid(raise_exception=True)

        started = time.monotonic()
        witness_cbor, _ = issue_witness(
            tx_cbor=serializer.validated_data["tx"],
            environment=environment,
            env_settings=env_settings,
            ip_address=ip_address,
            networks=list(settings.ENVIRONMENTS.keys()),
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        # Deliberately omit both client IP and transaction hash. Keeping
        # those together creates a durable link between a network identity
        # and an on-chain transaction, contrary to the service's privacy
        # goal. The request ID still correlates this line with errors and
        # timings from the same request without becoming an on-chain handle.
        logger.info(
            "Witness issued: env=%s duration_ms=%d",
            environment,
            duration_ms,
            extra={
                "env": environment,
                "duration_ms": duration_ms,
            },
        )
        return Response({"witness": witness_cbor}, status=status.HTTP_200_OK)


@extend_schema(
    operation_id="healthz",
    summary="Liveness/readiness check",
    description=(
        "Returns 200 if the service is configured well enough to serve "
        "signing requests (the current signing key, verification key, and "
        "PKH are cryptographically consistent). "
        "Returns 503 with a list of problems otherwise. Suitable for "
        "readiness probes; not rate limited and never calls Koios."
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
    problems = readiness_problems()
    if problems:
        response = Response(
            {"status": "error", "problems": problems},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    else:
        response = Response(
            {"status": "ok", "version": settings.SPECTACULAR_SETTINGS["VERSION"]},
            status=status.HTTP_200_OK,
        )
    # Don't let an upstream proxy cache "ok" past the moment the keys
    # disappear (or vice versa).
    response["Cache-Control"] = "no-store"
    return response


@extend_schema(
    operation_id="livez",
    summary="Process liveness check",
    description="Returns 200 whenever Django can serve requests. Never calls an upstream.",
    responses={200: OpenApiResponse(description="Process is alive.")},
)
@api_view(["GET"])
@throttle_classes([])
def livez_view(request):
    response = Response(
        {"status": "ok", "version": settings.SPECTACULAR_SETTINGS["VERSION"]},
        status=status.HTTP_200_OK,
    )
    response["Cache-Control"] = "no-store"
    return response


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
        logger.warning("Rejected unauthorized /metrics request")
        return HttpResponse(status=403)
    return HttpResponse(generate_latest(), content_type=CONTENT_TYPE_LATEST)


@require_GET
def landing_page(request):
    """Render the public landing page. Shows the provider's PKH so a user
    can confirm they're talking to the right provider, plus the network
    config from known.hosts.json keyed by that PKH."""
    hosts = _load_known_hosts()
    entry = hosts.get(settings.PKH)
    # Extract the network -> {utxo, url} mapping for the friendly cards;
    # ``public_key`` lives at the same depth but isn't a network. Fall
    # back to an empty list so the template can render an explicit
    # "not registered" notice rather than a confusing empty section.
    networks = []
    if isinstance(entry, dict):
        for name, cfg in entry.items():
            if name == "public_key" or not isinstance(cfg, dict):
                continue
            utxo = cfg.get("utxo") or {}
            networks.append({
                "name": name,
                "url": cfg.get("url", ""),
                "utxo_id": utxo.get("id", ""),
                "utxo_idx": utxo.get("idx", 0),
            })
    # Pre-fill the curl example with a real configured network when one is
    # available so a visitor can copy-paste without first having to read
    # the network list above. Falls back to a literal placeholder when the
    # PKH isn't registered yet.
    example_network = networks[0]["name"] if networks else "<network>"
    return render(
        request,
        "api/landing.html",
        {
            "pkh": settings.PKH,
            "networks": networks,
            "registered": isinstance(entry, dict),
            "version": settings.SPECTACULAR_SETTINGS["VERSION"],
            "example_network": example_network,
        },
    )


@require_GET
def known_hosts_view(request):
    """Return the last fully validated known-hosts registry as JSON.

    Returns ``{}`` if the file has never existed, so consumers don't have to
    handle a second shape. ``Cache-Control: no-store`` prevents an upstream
    proxy from serving stale discovery data after a hot reload.
    """
    response = JsonResponse(_load_known_hosts())
    response["Cache-Control"] = "no-store"
    return response


def custom_page_not_found(request, exception):
    return redirect("/")


def custom_disallowed_host_handler(request, exception):
    # request.get_host() can itself raise DisallowedHost; pull the raw
    # header instead so we always log something useful.
    raw = request.META.get("HTTP_HOST", "<missing>")
    logger.warning("DisallowedHost: %s", raw)
    return HttpResponseBadRequest("Invalid Host Header")
