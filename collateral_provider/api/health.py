"""Local liveness/readiness checks with no external network dependency."""

import logging
import os

from django.conf import settings

from api.signature import validate_key_material

logger = logging.getLogger("api")


def readiness_problems() -> list[str]:
    """Return public-safe labels for conditions that prevent signing.

    This deliberately does not call Koios: tying load-balancer readiness to a
    transient public upstream outage would recycle healthy workers precisely
    when retaining capacity matters most. Upstream health belongs in metrics
    and diagnostics. The signing identity is checked cryptographically on each
    probe so a broken hot key rotation is detected immediately.
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
    return []
