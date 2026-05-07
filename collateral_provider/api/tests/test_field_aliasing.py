"""Pin the request-field migration contract.

The canonical name is ``tx``. The historical name ``tx_body`` was misleading
(the value is the whole transaction, not just the body) and is being
phased out, but we accept it for one transition release so existing
clients keep working without a coordinated upgrade.
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from api.tests.test_views import build_happy_path_tx_cbor


@override_settings(ALLOWED_HOSTS=["testserver"])
class TestFieldAliasing(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("collateral", kwargs={"environment": "preprod"})

    def tearDown(self):
        cache.clear()

    @patch("api.validators.transaction.evaluate_transaction")
    def test_canonical_field_tx_works(self, mock_eval):
        mock_eval.return_value = {"jsonrpc": "2.0", "result": []}
        response = self.client.post(
            self.url, {"tx": build_happy_path_tx_cbor()}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("witness", response.json())

    @patch("api.validators.transaction.evaluate_transaction")
    def test_legacy_field_tx_body_still_works(self, mock_eval):
        # 1.0 clients on the wire send tx_body. They must keep working
        # for one release after the rename.
        mock_eval.return_value = {"jsonrpc": "2.0", "result": []}
        response = self.client.post(
            self.url, {"tx_body": build_happy_path_tx_cbor()}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("witness", response.json())

    def test_sending_both_is_rejected(self):
        # Ambiguous — refuse rather than silently picking one.
        response = self.client.post(
            self.url,
            {"tx": "deadbeef", "tx_body": "cafebabe"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("tx_body", response.json()["detail"])

    def test_neither_field_is_rejected(self):
        response = self.client.post(self.url, {}, format="json")
        self.assertEqual(response.status_code, 400)
