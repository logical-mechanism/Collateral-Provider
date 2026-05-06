import logging
import re
import time
import uuid
from contextvars import ContextVar

from api.metrics import http_request_duration_seconds, http_requests_total

# Default "-" is what shows up in logs emitted outside any request (startup,
# management commands, ad-hoc shell). Real request IDs are 12 hex chars.
_request_id: ContextVar[str] = ContextVar("request_id", default="-")


def get_request_id() -> str:
    """Return the current request's ID, or "-" if called outside a request."""
    return _request_id.get()


class RequestIDMiddleware:
    """Tag every request with an X-Request-ID for log correlation.

    If the client supplies X-Request-ID we honor it (so they can grep the
    same id across our logs and theirs). Otherwise we mint one. The id is
    stored in a contextvar so the logging filter can pick it up from any
    code path the request touches.
    """

    HEADER = "HTTP_X_REQUEST_ID"
    RESPONSE_HEADER = "X-Request-ID"
    MAX_INCOMING_LEN = 64

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        incoming = request.META.get(self.HEADER, "").strip()
        # Cap incoming length so a malicious client can't pump our logs full
        # of multi-kilobyte "request ids".
        rid = incoming[: self.MAX_INCOMING_LEN] if incoming else uuid.uuid4().hex[:12]
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
_COLLATERAL_PATH_RE = re.compile(r"^/(?P<env>[^/]+)/collateral/?$")


class MetricsMiddleware:
    """Count and time requests to the /<env>/collateral/ endpoint.

    Deliberately scoped: we don't want a label per URL path or per IP
    (cardinality + privacy). Other endpoints rely on Koios-specific metrics
    in api/metrics.py or aren't worth observing.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        match = _COLLATERAL_PATH_RE.match(request.path)
        if not match:
            return self.get_response(request)

        env = match.group("env")
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
