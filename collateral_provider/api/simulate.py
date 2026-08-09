import json
import logging
import secrets
import time
from threading import BoundedSemaphore, Condition, Lock

import requests
from django.conf import settings
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from api.metrics import koios_request_duration_seconds, koios_requests_total

logger = logging.getLogger("api")

# Connect quickly, fail quickly. Koios responds in well under a second on the
# happy path; anything beyond a few seconds is the user waiting for a 502.
# Connect bumped from 3s to 5s to absorb the occasional slow TLS handshake
# on a path the pooled Session below hasn't reached in a while.
DEFAULT_TIMEOUT = (5.0, 5.0)  # (connect, read)

PROTOCOL_PARAMETERS_TIMEOUT = (3.0, 5.0)  # (connect, read)
PROTOCOL_PARAMETERS_MAX_RESPONSE_BYTES = 256 * 1024
PROTOCOL_COST_MODELS_CACHE_SECONDS = 300.0
EVALUATION_MAX_RESPONSE_BYTES = 1024 * 1024
_PLUTUS_LANGUAGES = {
    "plutus:v1": 0,
    "plutus:v2": 1,
    "plutus:v3": 2,
    "plutus:v4": 3,
}
_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1

# A requests HTTPAdapter pool is not an admission limit unless pool_block is
# enabled. Keep an explicit nonblocking budget so slow Koios calls cannot pin
# every gunicorn thread and starve local health/error responses.
_upstream_slots = BoundedSemaphore(settings.KOIOS_MAX_IN_FLIGHT)
_protocol_cost_models_cache: dict[
    tuple[str, str], tuple[float, dict[int, tuple[int, ...]]]
] = {}
_protocol_cost_models_cache_lock = Lock()
_protocol_cost_models_condition = Condition(_protocol_cost_models_cache_lock)
_protocol_cost_models_refreshing: set[tuple[str, str]] = set()

# Module-level Session so TCP + TLS state is reused across requests. Without
# this, each call does a fresh handshake — fine warm, but after an idle stretch
# the first request pays the full setup cost, which is the dominant cause of
# cold-hit latency spikes that surface as 504s at the platform LB.
_session = requests.Session()
_adapter = HTTPAdapter(
    pool_connections=4,
    pool_maxsize=16,
    max_retries=Retry(total=0),
)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)


class UpstreamUnavailable(Exception):
    """The Koios evaluateTransaction endpoint could not be reached or returned
    a response that isn't a real verdict on the submitted transaction
    (network failure, 5xx, non-JSON body)."""


class ProtocolParametersUnavailable(Exception):
    """Ogmios could not provide trustworthy current Plutus cost models."""


class UpstreamResponseTooLarge(ValueError):
    """An upstream response exceeded the operation's byte budget."""


def _read_limited_response(response, limit: int) -> bytes:
    """Stream at most ``limit`` decompressed bytes from a response.

    Inspecting ``response.content`` after a normal requests call is too late:
    requests has already buffered the entire body. ``iter_content`` applies
    the bound during download, including when compressed content expands.
    """
    content_length = response.headers.get("Content-Length")
    if isinstance(content_length, str):
        try:
            parsed_length = int(content_length)
        except ValueError:
            # A malformed length is not authoritative; the streaming bound
            # below remains the source of truth.
            parsed_length = 0
        if parsed_length > limit:
            raise UpstreamResponseTooLarge()

    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        size += len(chunk)
        if size > limit:
            raise UpstreamResponseTooLarge()
        chunks.append(chunk)
    return b"".join(chunks)


def _acquire_upstream_slot(environment: str, operation: str, exception_type):
    if _upstream_slots.acquire(blocking=False):
        return
    koios_requests_total.labels(environment=environment, outcome="capacity").inc()
    logger.warning("Koios admission budget exhausted for %s (%s)", environment, operation)
    raise exception_type(f"koios {environment} is at local capacity")


def _clear_protocol_cost_models_cache() -> None:
    """Clear the small process-local cache (primarily for deterministic tests)."""
    with _protocol_cost_models_condition:
        _protocol_cost_models_cache.clear()
        _protocol_cost_models_refreshing.clear()
        _protocol_cost_models_condition.notify_all()


def _parse_protocol_cost_models(body: object) -> dict[int, tuple[int, ...]]:
    if not isinstance(body, dict):
        raise ProtocolParametersUnavailable("protocol parameters response is not an object")
    models = body.get("plutusCostModels")
    if not isinstance(models, dict) or not models:
        raise ProtocolParametersUnavailable("protocol cost models are missing")

    # A hard fork that introduces a language beyond plutus:v4 would otherwise
    # take the whole service down: rejecting the entire set turns every
    # request into a 503, including transactions using only languages whose
    # models we do understand. Skip what we cannot encode and fail only when
    # nothing usable remains. A transaction that genuinely needs the unknown
    # language still fails its script-data-hash check, which is a rejected
    # transaction rather than a scheduled outage.
    unknown = sorted(name for name in models if name not in _PLUTUS_LANGUAGES)
    if unknown:
        logger.warning(
            "Ignoring unknown Plutus cost model languages: %s", ", ".join(unknown)
        )
    models = {name: value for name, value in models.items() if name in _PLUTUS_LANGUAGES}
    if not models:
        raise ProtocolParametersUnavailable("no known protocol cost model languages")

    parsed: dict[int, tuple[int, ...]] = {}
    for name, parameters in models.items():
        if (
            not isinstance(parameters, list)
            or not parameters
            or len(parameters) > 1024
        ):
            raise ProtocolParametersUnavailable("protocol cost model is malformed")
        normalized: list[int] = []
        for parameter in parameters:
            if (
                not isinstance(parameter, int)
                or isinstance(parameter, bool)
                or not _INT64_MIN <= parameter <= _INT64_MAX
            ):
                raise ProtocolParametersUnavailable(
                    "protocol cost model parameter is malformed"
                )
            normalized.append(parameter)
        parsed[_PLUTUS_LANGUAGES[name]] = tuple(normalized)
    return parsed


def _fetch_protocol_cost_models(
    environment: str,
    timeout: float | tuple[float, float] = PROTOCOL_PARAMETERS_TIMEOUT,
) -> dict[int, tuple[int, ...]]:
    """Query the current node protocol parameters for Plutus cost models.

    Script-data hashes commit to the language-specific cost models.  This
    lookup uses the same Ogmios endpoint as transaction evaluation and fails
    closed on every transport, JSON-RPC, or schema ambiguity.  A short
    process-local cache avoids a second upstream round trip for every signing
    request while naturally expiring across protocol-parameter changes.
    """
    env_settings = settings.ENVIRONMENTS.get(environment)
    if not env_settings:
        raise ProtocolParametersUnavailable(f"unknown environment: {environment}")

    url = env_settings["KOIOS_URL"]
    cache_key = (environment, url)
    now = time.monotonic()
    with _protocol_cost_models_cache_lock:
        cached = _protocol_cost_models_cache.get(cache_key)
        if cached is not None and cached[0] > now:
            return dict(cached[1])

    request_id = secrets.token_hex(16)
    method = "queryLedgerState/protocolParameters"
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
    }

    started = time.monotonic()
    _acquire_upstream_slot(
        environment, "protocol_parameters", ProtocolParametersUnavailable
    )
    try:
        try:
            response = _session.post(
                url,
                headers=headers,
                json=payload,
                timeout=timeout,
                stream=True,
                allow_redirects=False,
            )
            try:
                response_status = response.status_code
                response_body = (
                    _read_limited_response(
                        response, PROTOCOL_PARAMETERS_MAX_RESPONSE_BYTES
                    )
                    if response_status == 200
                    else b""
                )
            finally:
                response.close()
        finally:
            _upstream_slots.release()
    except UpstreamResponseTooLarge as exc:
        koios_request_duration_seconds.labels(environment=environment).observe(
            time.monotonic() - started
        )
        koios_requests_total.labels(
            environment=environment, outcome="protocol_params_malformed"
        ).inc()
        logger.warning(
            "Ogmios protocol parameters response was oversized for %s", environment
        )
        raise ProtocolParametersUnavailable(
            f"ogmios {environment} protocol parameters response was oversized"
        ) from exc
    except requests.Timeout as exc:
        koios_request_duration_seconds.labels(environment=environment).observe(
            time.monotonic() - started
        )
        koios_requests_total.labels(
            environment=environment, outcome="protocol_params_timeout"
        ).inc()
        logger.warning("Ogmios protocol parameters timed out for %s: %s", environment, exc)
        raise ProtocolParametersUnavailable(
            f"ogmios {environment} protocol parameters timed out"
        ) from exc
    except requests.RequestException as exc:
        koios_request_duration_seconds.labels(environment=environment).observe(
            time.monotonic() - started
        )
        koios_requests_total.labels(
            environment=environment, outcome="protocol_params_request_error"
        ).inc()
        logger.warning("Ogmios protocol parameters failed for %s: %s", environment, exc)
        raise ProtocolParametersUnavailable(
            f"ogmios {environment} protocol parameters failed"
        ) from exc

    koios_request_duration_seconds.labels(environment=environment).observe(
        time.monotonic() - started
    )
    if response_status != 200:
        koios_requests_total.labels(
            environment=environment, outcome="protocol_params_http_error"
        ).inc()
        logger.warning(
            "Ogmios protocol parameters returned %d for %s",
            response_status,
            environment,
        )
        raise ProtocolParametersUnavailable(
            f"ogmios {environment} protocol parameters returned {response_status}"
        )

    try:
        response_json = json.loads(response_body)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        koios_requests_total.labels(
            environment=environment, outcome="protocol_params_invalid_json"
        ).inc()
        logger.warning("Ogmios protocol parameters returned invalid JSON for %s", environment)
        raise ProtocolParametersUnavailable(
            f"ogmios {environment} protocol parameters returned invalid json"
        ) from exc

    if not (
        isinstance(response_json, dict)
        and response_json.get("jsonrpc") == "2.0"
        and response_json.get("id") == request_id
        and response_json.get("method") == method
        and "error" not in response_json
        and isinstance(response_json.get("result"), dict)
    ):
        koios_requests_total.labels(
            environment=environment, outcome="protocol_params_malformed"
        ).inc()
        logger.warning(
            "Ogmios returned mismatched protocol parameters for %s", environment
        )
        raise ProtocolParametersUnavailable(
            f"ogmios {environment} returned mismatched protocol parameters"
        )

    try:
        parsed = _parse_protocol_cost_models(response_json["result"])
    except ProtocolParametersUnavailable:
        koios_requests_total.labels(
            environment=environment, outcome="protocol_params_malformed"
        ).inc()
        logger.warning("Ogmios returned malformed protocol cost models for %s", environment)
        raise

    with _protocol_cost_models_cache_lock:
        _protocol_cost_models_cache[cache_key] = (
            time.monotonic() + PROTOCOL_COST_MODELS_CACHE_SECONDS,
            parsed,
        )
    koios_requests_total.labels(
        environment=environment, outcome="protocol_params_success"
    ).inc()
    return dict(parsed)


def get_protocol_cost_models(
    environment: str,
    timeout: float | tuple[float, float] = PROTOCOL_PARAMETERS_TIMEOUT,
) -> dict[int, tuple[int, ...]]:
    """Return current cost models with one in-flight refresh per cache key.

    A cold cache or five-minute expiry can be reached by every gunicorn thread
    at once. One thread performs the upstream query while peers wait for that
    exact ``(environment, URL)`` refresh, preventing a periodic request burst
    from consuming the entire upstream admission budget.
    """
    env_settings = settings.ENVIRONMENTS.get(environment)
    if not env_settings:
        raise ProtocolParametersUnavailable(f"unknown environment: {environment}")
    cache_key = (environment, env_settings["KOIOS_URL"])

    if isinstance(timeout, tuple):
        wait_seconds = float(timeout[0]) + float(timeout[1]) + 1.0
    else:
        wait_seconds = (float(timeout) * 2) + 1.0

    with _protocol_cost_models_condition:
        now = time.monotonic()
        cached = _protocol_cost_models_cache.get(cache_key)
        if cached is not None and cached[0] > now:
            return dict(cached[1])

        if cache_key in _protocol_cost_models_refreshing:
            completed = _protocol_cost_models_condition.wait_for(
                lambda: cache_key not in _protocol_cost_models_refreshing,
                timeout=wait_seconds,
            )
            if not completed:
                raise ProtocolParametersUnavailable(
                    f"ogmios {environment} protocol parameters refresh timed out"
                )
            cached = _protocol_cost_models_cache.get(cache_key)
            if cached is not None and cached[0] > time.monotonic():
                return dict(cached[1])
            raise ProtocolParametersUnavailable(
                f"ogmios {environment} protocol parameters refresh failed"
            )

        _protocol_cost_models_refreshing.add(cache_key)

    try:
        return _fetch_protocol_cost_models(environment, timeout=timeout)
    finally:
        with _protocol_cost_models_condition:
            _protocol_cost_models_refreshing.discard(cache_key)
            _protocol_cost_models_condition.notify_all()


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
    params: dict = {"transaction": {"cbor": tx_body_cbor_hex}}
    payload = {
        "jsonrpc": "2.0",
        # Correlate the response to this exact request. Koios/Ogmios echoes
        # JSON-RPC ids, which lets us reject a stale, cached, or otherwise
        # mismatched verdict instead of treating it as authority to sign.
        "id": secrets.token_hex(16),
        "method": "evaluateTransaction",
        "params": params,
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
    }

    started = time.monotonic()
    _acquire_upstream_slot(environment, "evaluate", UpstreamUnavailable)
    try:
        try:
            response = _session.post(
                url,
                headers=headers,
                json=payload,
                timeout=timeout,
                stream=True,
                allow_redirects=False,
            )
            try:
                response_status = response.status_code
                response_body = (
                    _read_limited_response(response, EVALUATION_MAX_RESPONSE_BYTES)
                    if 200 <= response_status < 300
                    or response_status in (400, 422)
                    else b""
                )
            finally:
                response.close()
        finally:
            _upstream_slots.release()
    except UpstreamResponseTooLarge as exc:
        koios_request_duration_seconds.labels(environment=environment).observe(
            time.monotonic() - started
        )
        koios_requests_total.labels(environment=environment, outcome="malformed").inc()
        logger.warning("Koios evaluation response was oversized for %s", environment)
        raise UpstreamUnavailable(
            f"koios {environment} returned an oversized evaluation response"
        ) from exc
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

    # Only the transaction-verdict statuses used by Koios are accepted below.
    # Redirects, auth failures, missing endpoints, and rate limiting are
    # service/configuration failures—not evidence that the user's tx is bad.
    if not (200 <= response_status < 300 or response_status in (400, 422)):
        koios_requests_total.labels(environment=environment, outcome="http_error").inc()
        logger.warning(
            "Koios returned %d for %s",
            response_status,
            environment,
        )
        raise UpstreamUnavailable(
            f"koios {environment} returned {response_status}"
        )

    # Successful HTTP responses plus Koios's documented 400/422 verdict
    # statuses must carry JSON. Anything unparsable is an upstream failure.
    try:
        body = json.loads(response_body)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        koios_requests_total.labels(environment=environment, outcome="invalid_json").inc()
        logger.warning(
            "Koios returned non-JSON (status=%d) for %s: %s",
            response_status, environment, exc,
        )
        raise UpstreamUnavailable(
            f"koios {environment} returned invalid json (status {response_status})"
        ) from exc

    if not (
        isinstance(body, dict)
        and body.get("jsonrpc") == "2.0"
        and body.get("id") == payload["id"]
        and body.get("method") == "evaluateTransaction"
        and (("result" in body) != ("error" in body))
    ):
        koios_requests_total.labels(environment=environment, outcome="malformed").inc()
        logger.warning("Koios returned a mismatched JSON-RPC response for %s", environment)
        raise UpstreamUnavailable(
            f"koios {environment} returned a mismatched JSON-RPC response"
        )

    outcome = "success" if "result" in body else "tx_invalid"
    koios_requests_total.labels(environment=environment, outcome=outcome).inc()
    return body
