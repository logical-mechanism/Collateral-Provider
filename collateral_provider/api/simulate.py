import logging

import requests

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
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "evaluateTransaction",
        "params": {"transaction": {"cbor": tx_body_cbor_hex}},
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
    }
    prefix = "api" if environment == "mainnet" else environment
    url = f"https://{prefix}.koios.rest/api/v1/ogmios"
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.Timeout as exc:
        logger.warning(f"Koios timeout for {prefix}: {exc}")
        raise UpstreamUnavailable(f"koios {prefix} timed out") from exc
    except requests.RequestException as exc:
        logger.warning(f"Koios request failed for {prefix}: {exc}")
        raise UpstreamUnavailable(f"koios {prefix} request failed") from exc
    except ValueError as exc:
        logger.warning(f"Koios returned non-JSON for {prefix}: {exc}")
        raise UpstreamUnavailable(f"koios {prefix} returned invalid json") from exc
