"""Content negotiation for a service that speaks exactly one media type.

Kept in its own module rather than in ``api.util``: DRF resolves
``DEFAULT_CONTENT_NEGOTIATION_CLASS`` lazily from a settings string, and
``api.util`` is imported early by the validators, so putting the class there
makes DRF try to read it from a partially initialized module.
"""

from rest_framework.negotiation import DefaultContentNegotiation


class JSONOnlyContentNegotiation(DefaultContentNegotiation):
    """Always answer JSON, whatever the client's ``Accept`` header says.

    DRF's default negotiation returns 406 to a caller asking for
    ``text/html`` — and with the browsable renderer enabled it did something
    worse, handing back an HTML page instead of the documented
    ``{"detail": ...}`` envelope. Neither is useful to an integrator whose SDK
    forwards an end user's Accept header. Answering JSON unconditionally makes
    the response shape a property of the endpoint rather than of the caller's
    headers.

    Only *renderer* selection is relaxed. Parser negotiation is inherited
    unchanged, so a form-encoded or multipart body still gets the documented
    415 rather than being silently accepted.
    """

    def select_renderer(self, request, renderers, format_suffix=None):
        return (renderers[0], renderers[0].media_type)
