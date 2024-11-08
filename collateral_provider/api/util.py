# utils.py

from rest_framework import serializers


def log_and_raise_error(logger, message, log_level="error"):
    # Log the error with the specified logging level
    getattr(logger, log_level)(message)
    # Raise the ValidationError with the message
    raise serializers.ValidationError(message)
