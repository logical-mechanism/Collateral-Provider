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
        from api.signature import get_key_from_file

        for path in (settings.SKEY_PATH, settings.VKEY_PATH):
            if not os.path.exists(path):
                logger.critical(f"Signing key missing: {path}")
                raise RuntimeError(f"Required signing key not found at {path}")
            try:
                get_key_from_file(path)
            except (OSError, KeyError, ValueError, TypeError) as exc:
                logger.critical(f"Signing key unreadable at {path}: {exc}")
                raise RuntimeError(f"Could not parse signing key at {path}") from exc
