"""Pin two protocol-level request constraints:

1. The collateral endpoint accepts JSON bodies only — form-encoded and
   multipart bodies are documented as out of scope and must 415, so a
   client can't sneak a `tx` in via `application/x-www-form-urlencoded`.
2. Bodies above DATA_UPLOAD_MAX_MEMORY_SIZE are rejected before any view
   code or JSON parsing runs, including when Content-Length is absent.
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestParserLockedToJson(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("collateral", kwargs={"environment": "preprod"})

    def tearDown(self):
        cache.clear()

    def test_form_encoded_post_returns_415(self):
        # APIClient.post() with multipart format is the realistic browser-
        # leaning shape; DRF should refuse it now that we lock to JSON only.
        response = self.client.post(self.url, {"tx": "deadbeef"}, format="multipart")
        self.assertEqual(response.status_code, 415)

    def test_json_post_still_works(self):
        # The default format is JSON when content-type is application/json,
        # and that path must keep working for everyone.
        response = self.client.post(self.url, {"tx": "not-hex"}, format="json")
        # 400 from the validator (junk hex), not 415 — the parser accepted
        # it, the validator rejected it.
        self.assertEqual(response.status_code, 400)


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestBodySizeCap(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("collateral", kwargs={"environment": "preprod"})

    def tearDown(self):
        cache.clear()

    @patch("api.views.ProvideCollateralView.post")
    def test_oversize_content_length_rejected_before_view(self, mock_view):
        oversized = "a" * (200 * 1024)
        response = self.client.post(self.url, {"tx": oversized}, format="json")

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {"detail": "Request Body Too Large"})
        mock_view.assert_not_called()

    @override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=128)
    @patch("api.views.ProvideCollateralView.post")
    def test_oversize_stream_without_content_length_rejected_before_view(
        self, mock_view
    ):
        request = RequestFactory().post(
            self.url,
            data=b"x" * 129,
            content_type="application/json",
        )
        request.META.pop("CONTENT_LENGTH", None)

        from api.middleware import RequestBodyLimitMiddleware

        response = RequestBodyLimitMiddleware(mock_view)(request)

        self.assertEqual(response.status_code, 413)
        self.assertJSONEqual(response.content, {"detail": "Request Body Too Large"})
        mock_view.assert_not_called()
