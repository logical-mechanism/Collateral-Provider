import logging

from django.conf import settings
from django.core.exceptions import DisallowedHost
from django.http import HttpResponseBadRequest

logger = logging.getLogger("api")


class HandleDisallowedHostMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.META.get('HTTP_HOST')
        host = host.split(':')[0]
        if host and host not in settings.ALLOWED_HOSTS:
            logger.warning(f"DisallowedHost: Invalid Host - {host}")
            return HttpResponseBadRequest("Invalid Host Header")
        # Try to handle the response within the context of the request
        try:
            response = self.get_response(request)
            return response
        except DisallowedHost as e:
            # If DisallowedHost is raised, log the warning
            logger.warning(f"DisallowedHost: {str(e)} - Host: {request.META.get('HTTP_HOST', 'unknown')}")
            return HttpResponseBadRequest("Invalid Host Header")
        except Exception as e:
            # Optionally catch any other exceptions
            logger.error(f"Unexpected error: {str(e)}")
            return HttpResponseBadRequest("An error occurred.")
