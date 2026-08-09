import logging
import re
import time
import uuid
from contextvars import ContextVar
from io import BytesIO

from django.conf import settings
from django.http import JsonResponse

from api.metrics import http_request_duration_seconds, http_requests_total

# Default "-" is what shows up in logs emitted outside any request (startup,
# management commands, ad-hoc shell). Real request IDs are 12 hex chars.
_request_id: ContextVar[str] = ContextVar("request_id", default="-")

# Request IDs are reflected in a response header and appear in every log
# record. Restrict client-supplied values to a conservative ASCII alphabet so
# they cannot inject control characters or structured-log delimiters. This
# still accepts UUIDs, W3C traceparent values, and the common ``service:id`` /
# ``service.id`` forms.
_SAFE_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*", re.ASCII)


def get_request_id() -> str:
    """Return the current request's ID, or "-" if called outside a request."""
    return _request_id.get()


class RequestIDMiddleware:
    """Tag every request with an X-Request-ID for log correlation.

    If the client supplies a safe X-Request-ID we honor it (so they can grep
    the same id across our logs and theirs). Otherwise we mint one. The id is
    stored in a contextvar so the logging filter can pick it up from any code
    path the request touches.
    """

    HEADER = "HTTP_X_REQUEST_ID"
    RESPONSE_HEADER = "X-Request-ID"
    MAX_INCOMING_LEN = 64

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        incoming = request.META.get(self.HEADER, "").strip()
        # Never truncate an invalid/overlong value into something that might
        # collide with a legitimate caller's ID. Mint a fresh local ID.
        incoming_is_safe = (
            len(incoming) <= self.MAX_INCOMING_LEN
            and _SAFE_REQUEST_ID_RE.fullmatch(incoming) is not None
        )
        rid = incoming if incoming_is_safe else uuid.uuid4().hex[:12]
        token = _request_id.set(rid)
        try:
            response = self.get_response(request)
            response[self.RESPONSE_HEADER] = rid
            return response
        finally:
            _request_id.reset(token)


class RequestIDLogFilter(logging.Filter):
    """Inject the current request id onto every log record so the configured
    formatter can include it."""

    def filter(self, record):
        record.request_id = get_request_id()
        return True


# Pattern for the only path we care to measure. Other paths (/, /healthz,
# /known_hosts/, /api/docs/) are either trivial or scraped infrequently.
COLLATERAL_PATH_RE = re.compile(r"^/(?P<env>[^/]+)/collateral/?$")


class RequestBodyLimitMiddleware:
    """Enforce the collateral request cap before DRF parses JSON.

    Django's ``DATA_UPLOAD_MAX_MEMORY_SIZE`` does not reliably stop streaming
    parsers before the view, and a missing transfer ``Content-Length`` must not
    turn that setting into a bypass. Read at most ``limit + 1`` bytes, reject
    overflow, then replay the bounded bytes to DRF.

    A request with no ``Content-Length`` is answered with 411 rather than
    being processed. Django bounds ``request`` by that header — with no header
    the stream yields nothing — so a chunked body would otherwise reach the
    serializer empty and the caller would be told "Missing required field:
    'tx'" for a request they sent correctly. Naming the real problem is worth
    more to an integrator than a misleading 400. The shipped nginx sets
    ``proxy_request_buffering on``, so it buffers a chunked client request and
    forwards it with a length; only direct-to-gunicorn callers see this.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method != "POST" or not COLLATERAL_PATH_RE.match(request.path):
            return self.get_response(request)

        limit = settings.DATA_UPLOAD_MAX_MEMORY_SIZE
        raw_length = request.META.get("CONTENT_LENGTH")
        if not raw_length:
            return JsonResponse(
                {"detail": "Content-Length Header Is Required"},
                status=411,
            )
        try:
            content_length = int(raw_length)
        except (TypeError, ValueError):
            return JsonResponse({"detail": "Invalid Content-Length"}, status=400)
        if content_length < 0:
            return JsonResponse({"detail": "Invalid Content-Length"}, status=400)
        if content_length > limit:
            return JsonResponse({"detail": "Request Body Too Large"}, status=413)

        body = request.read(limit + 1)
        if len(body) > limit:
            return JsonResponse({"detail": "Request Body Too Large"}, status=413)

        # ``request.read`` marks the original stream consumed. Preserve the
        # bounded body and replace the stream so DRF sees the request normally.
        request._body = body
        request._stream = BytesIO(body)
        return self.get_response(request)


class MetricsMiddleware:
    """Count and time requests to the /<env>/collateral/ endpoint.

    Deliberately scoped: we don't want a label per URL path or per IP
    (cardinality + privacy). Other endpoints rely on Koios-specific metrics
    in api/metrics.py or aren't worth observing.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        match = COLLATERAL_PATH_RE.match(request.path)
        if not match:
            return self.get_response(request)

        requested_env = match.group("env")
        # Route values are attacker-controlled. Label only configured
        # environments and coalesce every invalid value into one bounded
        # series, otherwise /foo/collateral, /bar/collateral, ... grows the
        # Prometheus registry without limit.
        env = requested_env if requested_env in settings.ENVIRONMENTS else "unknown"
        started = time.monotonic()
        response = self.get_response(request)
        http_request_duration_seconds.labels(environment=env).observe(
            time.monotonic() - started
        )
        http_requests_total.labels(
            environment=env,
            status=str(response.status_code),
        ).inc()
        return response
