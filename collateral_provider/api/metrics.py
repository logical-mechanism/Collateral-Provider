"""Prometheus metrics for the collateral provider.

Deliberately kept aggregated and low-cardinality. We don't label by IP,
PKH, tx_id, or user-agent — those would either grow unbounded or amount
to per-user tracking, both of which are out of scope for this service.

Labels we *do* use:
- ``environment`` — one of the configured networks (preprod, mainnet).
- ``status`` — HTTP response status code as an integer string.
- ``outcome`` — coarse Koios call result enum.
"""

from prometheus_client import Counter, Histogram

# HTTP layer ----------------------------------------------------------------

http_requests_total = Counter(
    "collateral_http_requests_total",
    "HTTP requests handled by the collateral endpoint, labeled by environment and status code.",
    labelnames=("environment", "status"),
)

http_request_duration_seconds = Histogram(
    "collateral_http_request_duration_seconds",
    "Wall-clock time spent serving requests to the collateral endpoint.",
    labelnames=("environment",),
    buckets=(0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# Koios upstream ------------------------------------------------------------

KOIOS_OUTCOMES = ("success", "tx_invalid", "timeout", "request_error", "http_error", "invalid_json")

koios_requests_total = Counter(
    "collateral_koios_requests_total",
    "Calls to the Koios evaluateTransaction endpoint, labeled by environment and outcome.",
    labelnames=("environment", "outcome"),
)

koios_request_duration_seconds = Histogram(
    "collateral_koios_request_duration_seconds",
    "Wall-clock time spent on Koios evaluateTransaction calls.",
    labelnames=("environment",),
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
