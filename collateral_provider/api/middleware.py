import logging

from django.core.exceptions import DisallowedHost
from django.http import HttpResponseBadRequest

logger = logging.getLogger("api")


class HandleDisallowedHostMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            # Intercept the DisallowedHost exception early and log it as a warning
            response = self.get_response(request)
        except DisallowedHost as e:
            # Log the disallowed host attempt
            logger.warning(f"DisallowedHost: {str(e)} - Host: {request.get_host()}")
            # Return a Bad Request response instead of raising an error
            return HttpResponseBadRequest("Invalid Host Header")
        return response
