"""Optional ``additional_utxos`` request field.

Forwards to Ogmios as ``additionalUtxo`` so script evaluation can see UTxOs
created by transactions not yet on chain. Per-design: missing or empty is
fine and skipped silently; non-empty is forwarded verbatim — Koios returns
a real verdict if the inner shape is wrong, which surfaces to the caller as
a normal `Transaction Fails Validation` 400.
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from api.tests.test_views import build_happy_path_tx_cbor


def _sample_extra_utxo() -> list:
    return [
        [
            {"transaction": {"id": "a" * 64}, "index": 0},
            {
                "address": "addr_test1qz...",
                "value": {"ada": {"lovelace": 1_500_000}},
            },
        ]
    ]


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestAdditionalUtxosPassThrough(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("collateral", kwargs={"environment": "preprod"})

    def tearDown(self):
        cache.clear()

    @patch("api.validators.transaction.evaluate_transaction")
    def test_field_absent_means_no_additional_utxos_forwarded(self, mock_eval):
        mock_eval.return_value = {"jsonrpc": "2.0", "result": []}
        response = self.client.post(
            self.url, {"tx": build_happy_path_tx_cbor()}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(mock_eval.call_args.kwargs.get("additional_utxos"), None)

    @patch("api.validators.transaction.evaluate_transaction")
    def test_empty_list_is_treated_as_skip(self, mock_eval):
        mock_eval.return_value = {"jsonrpc": "2.0", "result": []}
        response = self.client.post(
            self.url,
            {"tx": build_happy_path_tx_cbor(), "additional_utxos": []},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        # An empty list is "incomplete" — skipped, never reaches Koios.
        self.assertEqual(mock_eval.call_args.kwargs.get("additional_utxos"), None)

    @patch("api.validators.transaction.evaluate_transaction")
    def test_non_empty_list_forwarded_verbatim(self, mock_eval):
        mock_eval.return_value = {"jsonrpc": "2.0", "result": []}
        extra = _sample_extra_utxo()
        response = self.client.post(
            self.url,
            {"tx": build_happy_path_tx_cbor(), "additional_utxos": extra},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(mock_eval.call_args.kwargs.get("additional_utxos"), extra)

    @patch("api.validators.transaction.evaluate_transaction")
    def test_malformed_inner_entry_is_still_passed_through(self, mock_eval):
        # Per design we do not mirror Ogmios's UTxO schema. If the user
        # sends an inner shape that's wrong, Koios returns a real verdict
        # and the request 400s with our standard tx-fails-validation message.
        mock_eval.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": "Bad UTxO"},
        }
        response = self.client.post(
            self.url,
            {
                "tx": build_happy_path_tx_cbor(),
                "additional_utxos": [["only-one-element-instead-of-pair"]],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("Transaction Fails Validation", response.json()["detail"])
