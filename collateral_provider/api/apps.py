import logging
import os
import sys

from django.apps import AppConfig
from django.conf import settings

logger = logging.getLogger("api")


class ApiConfig(AppConfig):
    name = "api"

    def ready(self) -> None:
        # Skip validation when collecting static files, generating migrations,
        # etc. — those don't need signing keys.
        if any(cmd in sys.argv for cmd in ("collectstatic", "makemigrations", "test")):
            return
        self._validate_signing_keys()

    def _validate_signing_keys(self) -> None:
        """Fail loudly at process start if the skey/vkey aren't readable.

        Without this, a bad deploy would only surface on the first POST
        request, returning a 500 to the user. Better to refuse to start."""
        from api.signature import validate_key_material

        for path in (settings.SKEY_PATH, settings.VKEY_PATH):
            if not os.path.exists(path):
                logger.critical(f"Signing key missing: {path}")
                raise RuntimeError(f"Required signing key not found at {path}")
        try:
            validate_key_material(settings.SKEY_PATH, settings.VKEY_PATH, settings.PKH)
        except (OSError, KeyError, ValueError, TypeError) as exc:
            logger.critical("Signing identity is invalid: %s", exc)
            raise RuntimeError("Signing key, verification key, and PKH do not match") from exc

        # Local operators commonly configure preprod first and leave mainnet
        # blank while developing. Production advertises both routes, so every
        # configured network must be usable there.
        if settings.ENVIRONMENT != "development":
            for environment, config in settings.ENVIRONMENTS.items():
                try:
                    txid = bytes.fromhex(config["TXID"])
                    txidx = config["TXIDX"]
                except (KeyError, TypeError, ValueError) as exc:
                    raise RuntimeError(
                        f"Invalid collateral configuration for {environment}"
                    ) from exc
                if (
                    len(txid) != 32
                    or not isinstance(txidx, int)
                    or isinstance(txidx, bool)
                    or txidx < 0
                ):
                    raise RuntimeError(f"Invalid collateral configuration for {environment}")
