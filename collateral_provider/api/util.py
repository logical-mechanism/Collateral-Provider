import logging
from typing import NoReturn

from rest_framework import serializers
from rest_framework.views import exception_handler as drf_exception_handler

logger = logging.getLogger("api")


def raise_validation_error(message: str) -> NoReturn:
    """Log and raise a DRF ValidationError. Use for any client-facing input
    error that should surface as a 400 with the given message.

    Logged at WARNING because these are *user* errors (the client sent us
    something we won't sign), not server errors. Reserve ERROR for things
    that page the on-call."""
    logger.warning(message)
    raise serializers.ValidationError(message)


def _first_message(payload) -> str:
    """Recurse into DRF's error structures and return the first leaf string."""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, list) and payload:
        return _first_message(payload[0])
    if isinstance(payload, dict) and payload:
        return _first_message(next(iter(payload.values())))
    return "Invalid Request"


def normalize_error_response(exc, context):
    """DRF exception handler that collapses every error response to a single
    {"detail": <string>} shape.

    DRF's default returns {field: [msg]} for serializer validation errors and
    {"detail": msg} for everything else. Clients shouldn't have to handle
    both shapes, especially since the field names would leak our internal
    structure. Surface the first human-readable message under "detail"
    and call it a day.
    """
    response = drf_exception_handler(exc, context)
    if response is None:
        return None

    data = response.data
    if isinstance(data, dict) and "detail" in data and isinstance(data["detail"], str):
        # Already in the canonical shape — pass through.
        return response

    response.data = {"detail": _first_message(data)}
    return response
