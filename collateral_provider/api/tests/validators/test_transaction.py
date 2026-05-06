import unittest
from unittest.mock import Mock, patch

from rest_framework.exceptions import ValidationError

from api.simulate import UpstreamUnavailable
from api.validators.transaction import (
    TransactionValidator,
    UpstreamServiceUnavailable,
)


class TestTransactionValidator(unittest.TestCase):
    def setUp(self):
        self.mock_logger = Mock()
        self.validator = TransactionValidator(self.mock_logger)

    @patch("api.validators.transaction.evaluate_transaction")
    def test_valid_tx_passes_silently(self, mock_eval):
        # Koios accepted the tx — response includes a 'result' key.
        mock_eval.return_value = {"jsonrpc": "2.0", "result": []}
        # No exception expected.
        self.validator.check_valid_tx("deadbeef", "preprod")
        mock_eval.assert_called_once_with("deadbeef", "preprod")

    @patch("api.validators.transaction.evaluate_transaction")
    def test_invalid_tx_raises_validation_error(self, mock_eval):
        # Koios rejected the tx — response carries an 'error', no 'result'.
        mock_eval.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": "Bad inputs"},
        }
        with self.assertRaises(ValidationError) as context:
            self.validator.check_valid_tx("deadbeef", "preprod")
        self.assertIn("Transaction Fails Validation", str(context.exception.detail))

    @patch("api.validators.transaction.evaluate_transaction")
    def test_upstream_failure_translates_to_503(self, mock_eval):
        # Koios was unreachable / timed out / returned junk. We must NOT
        # surface that as a 400 — the user's tx might be perfectly valid.
        mock_eval.side_effect = UpstreamUnavailable("koios preprod timed out")
        with self.assertRaises(UpstreamServiceUnavailable) as context:
            self.validator.check_valid_tx("deadbeef", "preprod")
        self.assertEqual(context.exception.status_code, 503)
        self.assertIn(
            "Validation Service Unavailable", str(context.exception.detail)
        )
