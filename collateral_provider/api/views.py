import ipaddress
import logging
import os
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
        _known_hosts = MtimeReloadingJson(path, default={})
    return _known_hosts


def _known_hosts_path() -> str:
    """Used by /healthz to report whether the known-hosts file is on disk."""
    return _known_hosts_loader().path


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


def _client_ip(request) -> str | None:
    """Best-effort client IP extraction.

    Only honors X-Forwarded-For when the immediate peer (Django's
    REMOTE_ADDR) is in ``settings.TRUSTED_PROXY_IPS``. Otherwise returns
    REMOTE_ADDR directly — a client connecting to gunicorn without the
    proxy in front can't spoof their source IP and bypass the per-IP
    throttle just by setting an X-Forwarded-For header.

    Entries in TRUSTED_PROXY_IPS may be bare IPs (``127.0.0.1``) or CIDR
    blocks (``10.0.0.0/8``). The latter is needed on container platforms
    that don't pin a single load-balancer IP.
    """
    remote = request.META.get("REMOTE_ADDR")
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff and _is_trusted_proxy(remote):
        return xff.split(",")[0].strip()
    return remote


class ProvideCollateralThrottle(throttling.AnonRateThrottle):
    # The real bottleneck is the Koios evaluation call, not us. Generous
    # for legit clients (one tx per second), tight enough that a single
    # bad actor can't exhaust an upstream rate limit on their own.
    rate = settings.COLLATERAL_THROTTLE_RATE

    def get_ident(self, request) -> str | None:
        """Use the same trusted-proxy-aware identity as bans and logs.

        DRF's default implementation consumes ``X-Forwarded-For`` according
        to its global ``NUM_PROXIES`` setting.  That is a separate trust model
        from this service's ``TRUSTED_PROXY_IPS`` allowlist and, with DRF's
        defaults, lets a directly-connected client forge a new throttle key
        merely by changing the header.  Keeping this override next to
        ``_client_ip`` makes the security boundary explicit and ensures bans,
        logging, and throttling agree about who made the request.
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
            415: OpenApiResponse(description="Unsupported media type — body must be application/json."),
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
                "Sample request with additional_utxos ([txin, txout] pair shape)",
                value={
                    "tx": "84a900d901028182582000...f5f6",
                    "additional_utxos": [
                        [
                            {"transaction": {"id": "ab" * 32}, "index": 0},
                            {
                                "address": "addr_test1qz...",
                                "value": {"ada": {"lovelace": 1500000}},
                            },
                        ],
                    ],
                },
                request_only=True,
                description=(
                    "Optional `additional_utxos` is forwarded to Ogmios as "
                    "`additionalUtxo` so script evaluation can see UTxOs "
                    "from a transaction not yet on chain. Each entry may "
                    "be a `[txin, txout]` pair (shown here, matching the "
                    "Ogmios prose docs) or a flat Ogmios v6 `Utxo` object "
                    "(see next example). Missing or empty is fine — the "
                    "field is skipped."
                ),
            ),
            OpenApiExample(
                "Sample request with additional_utxos (flat Utxo shape)",
                value={
                    "tx": "84a900d901028182582000...f5f6",
                    "additional_utxos": [
                        {
                            "transaction": {"id": "ab" * 32},
                            "index": 0,
                            "address": "addr_test1qz...",
                            "value": {"ada": {"lovelace": 1500000}},
                        },
                    ],
                },
                request_only=True,
                description=(
                    "Same field as the previous example, using the flat "
                    "Ogmios v6 `Utxo` shape — what callers learn when "
                    "building against Koios directly. Both shapes may be "
                    "mixed in one request."
                ),
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

        serializer = ProvideCollateralSerializer(data=request.data)
        # raise_exception=True lets the custom DRF exception handler
        # normalize the response shape to {"detail": "..."} consistently
        # with every other 4xx/5xx the API can produce. Validators inside
        # the service log their own warning-level reasons.
        serializer.is_valid(raise_exception=True)

        started = time.monotonic()
        witness_cbor, tx_hash = issue_witness(
            tx_cbor=serializer.validated_data["tx"],
            environment=environment,
            env_settings=env_settings,
            ip_address=ip_address,
            networks=list(settings.ENVIRONMENTS.keys()),
            additional_utxos=serializer.validated_data.get("additional_utxos"),
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        # Keep the structured fields on the record (JSON formatter
        # surfaces them as top-level keys) while also embedding them in
        # the message so the plain-text formatter prints something
        # operators can grep without changing the format string.
        logger.info(
            "Witnessed tx: ip=%s env=%s tx_hash=%s duration_ms=%d",
            ip_address, environment, tx_hash, duration_ms,
            extra={
                "ip": ip_address,
                "env": environment,
                "tx_hash": tx_hash,
                "duration_ms": duration_ms,
            },
        )
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
    # Two parallel lists: ``problems`` is what we return to the public
    # caller (label-only, no filesystem leak); ``log_problems`` carries
    # the absolute paths so the operator can grep their app log when
    # the LB starts seeing 503s. Don't merge the two — anything in
    # ``problems`` is world-readable.
    problems = []
    log_problems = []
    for label, path in (("skey", settings.SKEY_PATH), ("vkey", settings.VKEY_PATH)):
        if not os.path.exists(path):
            problems.append(f"{label} missing")
            log_problems.append(f"{label} missing at {path}")
        elif not os.access(path, os.R_OK):
            problems.append(f"{label} unreadable")
            log_problems.append(f"{label} unreadable at {path}")
    if not os.path.exists(_known_hosts_path()):
        problems.append("known_hosts missing")
        log_problems.append(f"known_hosts missing at {_known_hosts_path()}")

    if problems:
        for line in log_problems:
            logger.warning("healthz: %s", line)
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
    """Return the full known-hosts registry as JSON. Returns ``{}`` if the
    file is missing — that's the same response shape as an empty registry,
    so consumers don't have to handle two cases. ``Cache-Control: no-store``
    so an upstream proxy can't serve a stale registry after an operator
    edit (the file is hot-reloadable; caching defeats that)."""
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
