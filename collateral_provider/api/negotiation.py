"""Content negotiation for a service that speaks exactly one media type.

Kept in its own module rather than in ``api.util``: DRF resolves
``DEFAULT_CONTENT_NEGOTIATION_CLASS`` lazily from a settings string, and
``api.util`` is imported early by the validators, so putting the class there
makes DRF try to read it from a partially initialized module.
"""

from rest_framework.exceptions import NotAcceptable
from rest_framework.negotiation import DefaultContentNegotiation


class JSONOnlyContentNegotiation(DefaultContentNegotiation):
    """Never 406 — fall back to the view's first renderer instead.

    DRF's default negotiation returns 406 to a caller asking for
    ``text/html`` — and with the browsable renderer enabled it did something
    worse, handing back an HTML page instead of the documented
    ``{"detail": ...}`` envelope. Neither is useful to an integrator whose SDK
    forwards an end user's Accept header.

    Normal negotiation still runs first. Replacing it outright would break any
    view that legitimately offers more than one media type — notably
    drf-spectacular's schema endpoint, whose ``?format=json`` and
    ``Accept: application/json`` selection depend on it, and which would
    otherwise serve YAML under a JSON content type.

    Only *renderer* selection is relaxed. Parser negotiation is inherited
    unchanged, so a form-encoded or multipart body still gets the documented
    415 rather than being silently accepted.
    """

    def select_renderer(self, request, renderers, format_suffix=None):
        try:
            return super().select_renderer(request, renderers, format_suffix)
        except NotAcceptable:
            return (renderers[0], renderers[0].media_type)
