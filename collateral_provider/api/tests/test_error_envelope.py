"""Pin the contract that every 4xx/5xx response from a DRF view returns

    {"detail": <human-readable string>}

regardless of which DRF exception class fired or which serializer field
the validation error was raised against.
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestErrorEnvelope(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("collateral", kwargs={"environment": "preprod"})

    def tearDown(self):
        cache.clear()

    def test_validator_error_flattened_to_detail(self):
        # Non-hex tx -> our validators.cbor.check_cbor_hex raises
        # ValidationError("Invalid Hex Data In Tx"), which DRF would wrap as
        # {"tx": ["Invalid Hex Data In Tx"]}. The custom handler should
        # flatten that to {"detail": "Invalid Hex Data In Tx"}.
        response = self.client.post(self.url, {"tx": "not-hex"}, format="json")
        self.assertEqual(response.status_code, 400)
        body = response.json()
        self.assertEqual(set(body.keys()), {"detail"})
        self.assertEqual(body["detail"], "Invalid Hex Data In Tx")

    def test_invalid_environment_already_uses_detail(self):
        url = reverse("collateral", kwargs={"environment": "fakenet"})
        response = self.client.post(url, {"tx": "deadbeef"}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Invalid Environment"})

    def test_method_not_allowed_uses_detail(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)
        body = response.json()
        self.assertEqual(set(body.keys()), {"detail"})
        self.assertIn("not allowed", body["detail"].lower())

    @patch("api.validators.transaction.evaluate_transaction")
    def test_503_uses_detail(self, mock_eval):
        from api.simulate import UpstreamUnavailable
        from api.tests.test_views import TEST_COST_MODELS, build_happy_path_tx_cbor
        mock_eval.side_effect = UpstreamUnavailable("upstream down")

        with patch(
            "api.validators.transaction.get_protocol_cost_models",
            return_value=TEST_COST_MODELS,
        ):
            response = self.client.post(
                self.url, {"tx": build_happy_path_tx_cbor()}, format="json"
            )
        self.assertEqual(response.status_code, 503)
        body = response.json()
        self.assertEqual(set(body.keys()), {"detail"})
        self.assertEqual(body["detail"], "Validation Service Unavailable")

    def test_no_field_names_leak_in_400_response(self):
        # The response envelope must always be {"detail": "..."} — never a
        # field-keyed dict. The detail MESSAGE may name the field (it's part
        # of the public request contract and helps clients debug); what
        # matters is that the top-level shape is canonical.
        response = self.client.post(self.url, {"tx": "not-hex"}, format="json")
        self.assertEqual(response.status_code, 400)
        body = response.json()
        self.assertEqual(set(body.keys()), {"detail"})

    def test_missing_required_field_names_the_field(self):
        # DRF's default "This field is required." is undebuggable from the
        # wire — clients can't tell which field they forgot. Pin the
        # rephrased version so the next regression is obvious.
        response = self.client.post(self.url, {}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Missing required field: 'tx'"})

    def test_null_field_names_the_field(self):
        response = self.client.post(self.url, {"tx": None}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Field 'tx' may not be null"})

    def test_blank_field_names_the_field(self):
        response = self.client.post(self.url, {"tx": ""}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Field 'tx' may not be blank"})


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestEnvelopeSurvivesClientHeaders(TestCase):
    """The response shape must be a property of the endpoint, not the caller.

    DRF's default renderer list included the browsable API, so a client
    sending ``Accept: text/html`` received an HTML page instead of the
    documented envelope — on success as well as on error.
    """

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("collateral", kwargs={"environment": "preprod"})

    def tearDown(self):
        cache.clear()

    def test_html_accept_still_gets_json_envelope(self):
        for accept in ("text/html", "text/html,application/xhtml+xml", "*/*", "text/plain"):
            with self.subTest(accept=accept):
                response = self.client.post(
                    self.url, {"tx": "not-hex"}, format="json", HTTP_ACCEPT=accept
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response["Content-Type"], "application/json")
                self.assertEqual(response.json(), {"detail": "Invalid Hex Data In Tx"})


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestNotFoundEnvelope(TestCase):
    """A mistyped API URL must not look like a success.

    handler404 used to redirect everything to the landing page. Every
    mainstream HTTP client follows redirects by default, so an integrator
    POSTing to a misspelled path saw 200 and an HTML page.
    """

    def setUp(self):
        self.client = APIClient()

    def tearDown(self):
        cache.clear()

    def test_mistyped_collateral_path_returns_json_404(self):
        response = self.client.post(
            "/preprod/collaterall/", {"tx": "deadbeef"}, format="json"
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "Not Found"})

    def test_api_client_get_returns_json_404(self):
        response = self.client.get("/no/such/endpoint", HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "Not Found"})

    def test_browser_navigation_still_redirects_home(self):
        response = self.client.get("/an/old/link", HTTP_ACCEPT="text/html")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestNonDrfErrorEnvelope(TestCase):
    """Errors raised outside DRF must still use the documented envelope.

    DRF's exception handler returns None for anything that is not an
    APIException, which re-raises into Django's default HTML 500 page; and a
    rejected Host header never reaches DRF at all. Both used to hand the
    integrator a body they could not parse.
    """

    def tearDown(self):
        cache.clear()

    @patch("api.views.ProvideCollateralView.post", side_effect=RuntimeError("boom"))
    def test_unhandled_exception_returns_json_500(self, _mock_post):
        client = APIClient(raise_request_exception=False)
        url = reverse("collateral", kwargs={"environment": "preprod"})
        response = client.post(url, {"tx": "deadbeef"}, format="json")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json(), {"detail": "Internal Server Error"})

    def test_disallowed_host_returns_json_400(self):
        response = self.client.get("/", HTTP_HOST="evil.example")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json(), {"detail": "Invalid Host Header"})
