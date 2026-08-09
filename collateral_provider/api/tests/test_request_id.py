import logging
import unittest
from unittest.mock import patch

from django.test import RequestFactory, TestCase, override_settings

from api.middleware import (
    RequestIDLogFilter,
    RequestIDMiddleware,
    _request_id,
    get_request_id,
)


def _identity_response(request):
    from django.http import HttpResponse
    return HttpResponse("ok")


class TestRequestIDMiddleware(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = RequestIDMiddleware(_identity_response)

    def test_mints_uuid_when_no_client_header(self):
        request = self.factory.get("/")
        response = self.middleware(request)
        rid = response["X-Request-ID"]
        # Default minted IDs are 12 hex chars (uuid4().hex[:12]).
        self.assertRegex(rid, r"^[0-9a-f]{12}$")

    def test_honors_client_supplied_header(self):
        request = self.factory.get("/", HTTP_X_REQUEST_ID="trace-abc-123")
        response = self.middleware(request)
        self.assertEqual(response["X-Request-ID"], "trace-abc-123")

    def test_replaces_overlong_client_header(self):
        # Mint instead of truncating: two long IDs with the same prefix must
        # not collapse into one operator-visible correlation ID.
        long_id = "x" * 5000
        request = self.factory.get("/", HTTP_X_REQUEST_ID=long_id)
        response = self.middleware(request)
        self.assertRegex(response["X-Request-ID"], r"^[0-9a-f]{12}$")
        self.assertNotEqual(response["X-Request-ID"], long_id[:12])

    def test_accepts_safe_id_at_maximum_length(self):
        incoming = "a" + ("Z9._:-" * 11)[: RequestIDMiddleware.MAX_INCOMING_LEN - 1]
        self.assertEqual(len(incoming), RequestIDMiddleware.MAX_INCOMING_LEN)
        request = self.factory.get("/", HTTP_X_REQUEST_ID=incoming)
        response = self.middleware(request)
        self.assertEqual(response["X-Request-ID"], incoming)

    def test_replaces_log_injection_characters(self):
        incoming = "trace-ok\nWARNING forged-log-entry"
        request = self.factory.get("/", HTTP_X_REQUEST_ID=incoming)
        response = self.middleware(request)
        self.assertRegex(response["X-Request-ID"], r"^[0-9a-f]{12}$")
        self.assertNotIn("\n", response["X-Request-ID"])

    def test_replaces_non_ascii_and_structured_log_punctuation(self):
        for incoming in ('trace"fake":true', "trace/../../etc", "trace-☃"):
            with self.subTest(incoming=incoming):
                request = self.factory.get("/", HTTP_X_REQUEST_ID=incoming)
                response = self.middleware(request)
                self.assertRegex(response["X-Request-ID"], r"^[0-9a-f]{12}$")

    def test_id_set_during_request_cleared_after(self):
        seen = {}

        def inner(request):
            seen["during"] = get_request_id()
            from django.http import HttpResponse
            return HttpResponse("ok")

        mw = RequestIDMiddleware(inner)
        request = self.factory.get("/")
        mw(request)

        self.assertRegex(seen["during"], r"^[0-9a-f]{12}$")
        self.assertEqual(get_request_id(), "-")

    def test_blank_incoming_header_treated_as_missing(self):
        # Some proxies send the header with an empty value; we should mint
        # rather than echo an empty string back.
        request = self.factory.get("/", HTTP_X_REQUEST_ID="   ")
        response = self.middleware(request)
        self.assertNotEqual(response["X-Request-ID"].strip(), "")


class TestRequestIDLogFilter(unittest.TestCase):
    def test_filter_attaches_request_id_to_record(self):
        f = RequestIDLogFilter()
        token = _request_id.set("abc123def456")
        try:
            record = logging.LogRecord(
                name="api",
                level=logging.INFO,
                pathname=__file__,
                lineno=0,
                msg="hello",
                args=(),
                exc_info=None,
            )
            f.filter(record)
            self.assertEqual(record.request_id, "abc123def456")
        finally:
            _request_id.reset(token)

    def test_filter_uses_dash_when_outside_request(self):
        f = RequestIDLogFilter()
        record = logging.LogRecord(
            name="api",
            level=logging.INFO,
            pathname=__file__,
            lineno=0,
            msg="hello",
            args=(),
            exc_info=None,
        )
        f.filter(record)
        self.assertEqual(record.request_id, "-")


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestRequestIDOnRealResponses(TestCase):
    """End-to-end: hitting any view returns a request id header."""

    def test_landing_page_response_carries_id(self):
        response = self.client.get("/")
        self.assertIn("X-Request-ID", response.headers)
        self.assertRegex(response.headers["X-Request-ID"], r"^[0-9a-f]{12}$")

    def test_id_propagates_to_log_records(self):
        # Hit a view while capturing the api logger; confirm the record's
        # request_id matches the response header.
        captured = []

        class _Capture(logging.Handler):
            def emit(self, record):
                captured.append(record)

        api_logger = logging.getLogger("api")
        handler = _Capture()
        # Apply the same filter the file/console handlers use in prod.
        handler.addFilter(RequestIDLogFilter())
        api_logger.addHandler(handler)
        try:
            with patch("api.views._load_known_hosts", return_value={}):
                response = self.client.get("/")
        finally:
            api_logger.removeHandler(handler)

        rid = response.headers["X-Request-ID"]
        # We don't assert any particular log line was produced (the landing
        # page is quiet at INFO+). What matters is that *if* anything
        # logs during the request, request_id is set on the record.
        for record in captured:
            self.assertEqual(getattr(record, "request_id", None), rid)
        # Sanity: outside the request the contextvar resets.
        self.assertEqual(get_request_id(), "-")
