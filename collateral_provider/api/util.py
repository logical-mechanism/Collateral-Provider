import logging

from rest_framework import serializers

logger = logging.getLogger("api")


def raise_validation_error(message: str) -> None:
    """Log and raise a DRF ValidationError. Use for any client-facing input
    error that should surface as a 400 with the given message.

    Logged at WARNING because these are *user* errors (the client sent us
    something we won't sign), not server errors. Reserve ERROR for things
    that page the on-call."""
    logger.warning(message)
    raise serializers.ValidationError(message)
