import logging
import time

import requests
from django.conf import settings

from api.metrics import koios_request_duration_seconds, koios_requests_total

logger = logging.getLogger("api")

# Connect quickly, fail quickly. Koios responds in well under a second on the
# happy path; anything beyond a few seconds is the user waiting for a 502.
DEFAULT_TIMEOUT = (3.0, 5.0)  # (connect, read)


class UpstreamUnavailable(Exception):
    """The Koios evaluateTransaction endpoint could not be reached or returned
    a response that isn't a real verdict on the submitted transaction
    (network failure, 5xx, non-JSON body)."""


def evaluate_transaction(
    tx_body_cbor_hex: str,
    environment: str,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
) -> dict:
    """Submit the tx CBOR to Koios for script-evaluation simulation.

    Returns the parsed JSON-RPC response. The caller decides whether the
    response represents a valid tx (presence of ``result``) or an invalid
    one (``error``).

    Important nuance: Koios may report a tx-level error as either
    ``200 + {"error": ...}`` or ``4xx + {"error": ...}`` depending on the
    nature of the failure. We accept *both* as real verdicts so we don't
    misclassify a bad transaction as an upstream outage. Only network
    errors, timeouts, 5xx, and non-JSON bodies become ``UpstreamUnavailable``
    (which the view layer translates to a 503).

    The endpoint URL is taken from
    ``settings.ENVIRONMENTS[<env>]['KOIOS_URL']`` so operators can
    self-host Koios or use alternate networks (preview, sanchonet)
    without changing code.
    """
    env_settings = settings.ENVIRONMENTS.get(environment)
    if not env_settings:
        # Don't burn a metrics label on unknown envs.
        raise UpstreamUnavailable(f"unknown environment: {environment}")

    url = env_settings["KOIOS_URL"]
    payload = {
        "jsonrpc": "2.0",
        "method": "evaluateTransaction",
        "params": {"transaction": {"cbor": tx_body_cbor_hex}},
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
    }

    started = time.monotonic()
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=timeout)
    except requests.Timeout as exc:
        koios_request_duration_seconds.labels(environment=environment).observe(
            time.monotonic() - started
        )
        koios_requests_total.labels(environment=environment, outcome="timeout").inc()
        logger.warning("Koios timeout for %s: %s", environment, exc)
        raise UpstreamUnavailable(f"koios {environment} timed out") from exc
    except requests.RequestException as exc:
        koios_request_duration_seconds.labels(environment=environment).observe(
            time.monotonic() - started
        )
        koios_requests_total.labels(environment=environment, outcome="request_error").inc()
        logger.warning("Koios request failed for %s: %s", environment, exc)
        raise UpstreamUnavailable(f"koios {environment} request failed") from exc

    koios_request_duration_seconds.labels(environment=environment).observe(
        time.monotonic() - started
    )

    # 5xx is a server-side problem with Koios itself, not a verdict on the
    # tx. Surface it as upstream-unavailable so the user gets a 503.
    if response.status_code >= 500:
        koios_requests_total.labels(environment=environment, outcome="http_error").inc()
        logger.warning(
            "Koios returned %d for %s: %s",
            response.status_code, environment, response.text[:200],
        )
        raise UpstreamUnavailable(
            f"koios {environment} returned {response.status_code}"
        )

    # 2xx and 4xx both might carry a real JSON-RPC verdict body. Try to
    # parse; only escalate to upstream-unavailable if the body isn't JSON
    # at all (which would mean Koios is hosed in a different way).
    try:
        body = response.json()
    except ValueError as exc:
        koios_requests_total.labels(environment=environment, outcome="invalid_json").inc()
        logger.warning(
            "Koios returned non-JSON (status=%d) for %s: %s",
            response.status_code, environment, exc,
        )
        raise UpstreamUnavailable(
            f"koios {environment} returned invalid json (status {response.status_code})"
        ) from exc

    outcome = "success" if "result" in body else "tx_invalid"
    koios_requests_total.labels(environment=environment, outcome=outcome).inc()
    return body
