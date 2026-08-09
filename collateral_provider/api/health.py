"""Local liveness/readiness checks with no external network dependency."""

import logging
import os

from django.conf import settings
from django.core.cache import cache

from api.signature import validate_key_material

logger = logging.getLogger("api")


def _cache_problem() -> str | None:
    """Round-trip the throttle cache, which every collateral POST depends on.

    The default CACHE_DIR lives inside the release tree, which the shipped
    systemd unit mounts read-only (ProtectSystem=strict). Without this probe a
    deploy whose environment file omits CACHE_DIR passes /healthz, satisfies
    the deploy script's readiness gate, never rolls back — and then 500s on
    every request, because the throttle cannot write its counter. Readiness
    must fail for the same reasons the endpoint does.
    """
    key = "healthz:cache-probe"
    try:
        cache.set(key, 1, 30)
        if cache.get(key) != 1:
            return "throttle cache not readable"
    except Exception as exc:
        logger.warning("readiness: throttle cache unusable: %s", exc)
        return "throttle cache unwritable"
    return None


def readiness_problems() -> list[str]:
    """Return public-safe labels for conditions that prevent signing.

    This deliberately does not call Koios: tying load-balancer readiness to a
    transient public upstream outage would recycle healthy workers precisely
    when retaining capacity matters most. Upstream health belongs in metrics
    and diagnostics. The signing identity is checked cryptographically on each
    probe so a broken hot key rotation is detected immediately, and the
    throttle cache is exercised because a collateral request cannot be served
    without it.
    """
    for label, path in (("skey", settings.SKEY_PATH), ("vkey", settings.VKEY_PATH)):
        if not os.path.exists(path):
            logger.warning("readiness: %s missing at %s", label, path)
            return [f"{label} missing"]
        if not os.access(path, os.R_OK):
            logger.warning("readiness: %s unreadable at %s", label, path)
            return [f"{label} unreadable"]

    try:
        validate_key_material(settings.SKEY_PATH, settings.VKEY_PATH, settings.PKH)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        logger.warning("readiness: invalid signing identity: %s", exc)
        return ["signing identity invalid"]

    cache_problem = _cache_problem()
    if cache_problem:
        return [cache_problem]
    return []
