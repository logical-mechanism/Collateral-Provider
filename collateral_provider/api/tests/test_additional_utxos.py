"""Regression tests for the deliberately unsupported additional-UTxO path."""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from api.tests.test_views import TEST_COST_MODELS, build_happy_path_tx_cbor

EVALUATION_RESPONSE = {
    "jsonrpc": "2.0",
    "method": "evaluateTransaction",
    "result": [
        {"validator": "spend:0", "budget": {"memory": 1, "cpu": 1}}
    ],
}


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestAdditionalUtxosUnsupported(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("collateral", kwargs={"environment": "preprod"})

    def tearDown(self):
        cache.clear()

    @patch(
        "api.validators.transaction.get_protocol_cost_models",
        return_value=TEST_COST_MODELS,
    )
    @patch("api.validators.transaction.evaluate_transaction")
    def test_empty_list_is_accepted_but_never_forwarded(self, mock_eval, _mock_models):
        mock_eval.return_value = EVALUATION_RESPONSE

        response = self.client.post(
            self.url,
            {"tx": build_happy_path_tx_cbor(), "additional_utxos": []},
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)
        mock_eval.assert_called_once_with(build_happy_path_tx_cbor(), "preprod")

    @override_settings(ALLOW_ADDITIONAL_UTXOS=True)
    @patch("api.validators.transaction.get_protocol_cost_models")
    @patch("api.validators.transaction.evaluate_transaction")
    def test_non_empty_list_cannot_be_enabled_by_a_legacy_setting(
        self, mock_eval, mock_models
    ):
        response = self.client.post(
            self.url,
            {
                "tx": build_happy_path_tx_cbor(),
                "additional_utxos": [
                    {
                        "transaction": {"id": "a" * 64},
                        "index": 0,
                        "address": "addr_test1...",
                        "value": {"ada": {"lovelace": 1_500_000}},
                    }
                ],
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(set(response.json()), {"detail"})
        self.assertIn("not supported", response.json()["detail"])
        mock_models.assert_not_called()
        mock_eval.assert_not_called()
