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
    a malformed/error response unrelated to the submitted transaction."""


def evaluate_transaction(
    tx_body_cbor_hex: str,
    environment: str,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
) -> dict:
    """Submit the tx CBOR to Koios for script-evaluation simulation.

    Returns the parsed JSON-RPC response on success. The caller decides
    whether the response represents a valid tx (presence of 'result') or an
    invalid one ('error'). Raises UpstreamUnavailable for anything that isn't
    a real verdict from Koios — network errors, timeouts, non-2xx HTTP, or
    non-JSON bodies.

    The endpoint URL is taken from settings.ENVIRONMENTS[<env>]['KOIOS_URL']
    so operators can self-host Koios or use alternate networks (preview,
    sanchonet) without changing code.
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
        response.raise_for_status()
        body = response.json()
    except requests.Timeout as exc:
        koios_requests_total.labels(environment=environment, outcome="timeout").inc()
        logger.warning("Koios timeout for %s: %s", environment, exc)
        raise UpstreamUnavailable(f"koios {environment} timed out") from exc
    except requests.HTTPError as exc:
        koios_requests_total.labels(environment=environment, outcome="http_error").inc()
        logger.warning("Koios returned non-2xx for %s: %s", environment, exc)
        raise UpstreamUnavailable(f"koios {environment} non-2xx") from exc
    except requests.RequestException as exc:
        koios_requests_total.labels(environment=environment, outcome="request_error").inc()
        logger.warning("Koios request failed for %s: %s", environment, exc)
        raise UpstreamUnavailable(f"koios {environment} request failed") from exc
    except ValueError as exc:
        koios_requests_total.labels(environment=environment, outcome="invalid_json").inc()
        logger.warning("Koios returned non-JSON for %s: %s", environment, exc)
        raise UpstreamUnavailable(f"koios {environment} returned invalid json") from exc
    finally:
        koios_request_duration_seconds.labels(environment=environment).observe(
            time.monotonic() - started
        )

    # 2xx response. The caller decides whether it represents a valid tx
    # (has 'result') or an invalid one (has 'error', no 'result'). We
    # record the outcome here so we can graph each separately.
    outcome = "success" if "result" in body else "tx_invalid"
    koios_requests_total.labels(environment=environment, outcome=outcome).inc()
    return body
