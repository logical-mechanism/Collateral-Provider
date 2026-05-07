import unittest
from unittest.mock import patch

from rest_framework.exceptions import ValidationError

from api.simulate import UpstreamUnavailable
from api.validators.transaction import (
    UpstreamServiceUnavailable,
    check_valid_tx,
)


class TestTransactionValidator(unittest.TestCase):
    @patch("api.validators.transaction.evaluate_transaction")
    def test_valid_tx_passes_silently(self, mock_eval):
        # Koios accepted the tx — response includes a 'result' key.
        mock_eval.return_value = {"jsonrpc": "2.0", "result": []}
        check_valid_tx("deadbeef", "preprod")
        mock_eval.assert_called_once_with("deadbeef", "preprod")

    @patch("api.validators.transaction.evaluate_transaction")
    def test_invalid_tx_raises_validation_error(self, mock_eval):
        # Koios rejected the tx — response carries an 'error', no 'result'.
        mock_eval.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": "Bad inputs"},
        }
        with self.assertRaises(ValidationError) as context:
            check_valid_tx("deadbeef", "preprod")
        self.assertIn("Transaction Fails Validation", str(context.exception.detail))

    @patch("api.validators.transaction.evaluate_transaction")
    def test_upstream_failure_translates_to_503(self, mock_eval):
        # Koios was unreachable / timed out / returned junk. We must NOT
        # surface that as a 400 — the user's tx might be perfectly valid.
        mock_eval.side_effect = UpstreamUnavailable("koios preprod timed out")
        with self.assertRaises(UpstreamServiceUnavailable) as context:
            check_valid_tx("deadbeef", "preprod")
        self.assertEqual(context.exception.status_code, 503)
        self.assertIn(
            "Validation Service Unavailable", str(context.exception.detail)
        )
