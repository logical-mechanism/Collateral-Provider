"""Optional ``additional_utxos`` request field.

Forwards to Ogmios as ``additionalUtxo`` so script evaluation can see UTxOs
created by transactions not yet on chain. Missing or empty is skipped
silently; entries must be ``[txin, txout]`` pairs of objects. Anything
else is rejected locally so we don't pay a Koios round-trip just to be
told the shape is wrong, and so the JSON-encoded payload can't exceed
``ADDITIONAL_UTXOS_MAX_BYTES``.
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
    def test_flat_utxo_object_entries_accepted_and_forwarded(self, mock_eval):
        # Callers that learned Ogmios v6's flat Utxo schema (e.g. by
        # building against Koios docs directly) can send entries as
        # single objects instead of [txin, txout] pairs. The serializer
        # accepts them; simulate.py is responsible for normalization.
        mock_eval.return_value = {"jsonrpc": "2.0", "result": []}
        flat = [
            {
                "transaction": {"id": "a" * 64},
                "index": 0,
                "address": "addr_test1qz...",
                "value": {"ada": {"lovelace": 1_500_000}},
            }
        ]
        response = self.client.post(
            self.url,
            {"tx": build_happy_path_tx_cbor(), "additional_utxos": flat},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(mock_eval.call_args.kwargs.get("additional_utxos"), flat)

    @patch("api.validators.transaction.evaluate_transaction")
    def test_entry_that_is_neither_pair_nor_object_rejected(self, mock_eval):
        # A bare string (or any non-list, non-dict) doesn't match either
        # accepted shape and must fail locally with a clear message.
        response = self.client.post(
            self.url,
            {
                "tx": build_happy_path_tx_cbor(),
                "additional_utxos": ["not-a-pair-or-object"],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("[txin, txout] pair or a flat Utxo object", response.json()["detail"])
        mock_eval.assert_not_called()

    @patch("api.validators.transaction.evaluate_transaction")
    def test_malformed_pair_rejected_locally_no_upstream_call(self, mock_eval):
        # An entry that isn't a 2-element [txin, txout] pair fails the
        # serializer's structural check before we issue the Koios call —
        # so the upstream is never reached.
        response = self.client.post(
            self.url,
            {
                "tx": build_happy_path_tx_cbor(),
                "additional_utxos": [["only-one-element-instead-of-pair"]],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("[txin, txout]", response.json()["detail"])
        mock_eval.assert_not_called()

    @patch("api.validators.transaction.evaluate_transaction")
    def test_oversized_additional_utxos_rejected_locally(self, mock_eval):
        # Build a payload that exceeds ADDITIONAL_UTXOS_MAX_BYTES (32 KiB)
        # by stuffing a giant string into a valid-shape entry.
        bloat = "x" * 40_000
        response = self.client.post(
            self.url,
            {
                "tx": build_happy_path_tx_cbor(),
                "additional_utxos": [
                    [
                        {"transaction": {"id": "a" * 64}, "index": 0},
                        {"address": "addr_test1qz...", "memo": bloat},
                    ]
                ],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("exceeds", response.json()["detail"])
        mock_eval.assert_not_called()
