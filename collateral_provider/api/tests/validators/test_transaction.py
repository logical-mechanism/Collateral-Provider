import unittest
from unittest.mock import patch

import cbor2
from rest_framework.exceptions import ValidationError

from api.script_integrity import calculate_script_data_hash
from api.simulate import (
    ProtocolParametersUnavailable,
    UpstreamUnavailable,
)
from api.validators.transaction import (
    UpstreamServiceUnavailable,
    check_valid_tx,
)

EVALUATION = {
    "validator": "spend:0",
    "budget": {"memory": 1, "cpu": 1},
}
COST_MODELS = {1: (4, 5)}


def _tx_cbor(redeemers) -> str:
    redeemer_bytes = cbor2.dumps(redeemers)
    script_data_hash = calculate_script_data_hash(
        redeemer_bytes, b"", COST_MODELS
    )
    return cbor2.dumps(
        [{11: script_data_hash}, {5: redeemers}, True, None]
    ).hex()


TX_CBOR = _tx_cbor({(0, 0): [cbor2.CBORTag(121, []), [10, 10]]})


def _evaluation_response(evaluations: list) -> dict:
    return {
        "jsonrpc": "2.0",
        "method": "evaluateTransaction",
        "result": evaluations,
    }


class TestTransactionValidator(unittest.TestCase):
    def setUp(self):
        self.models_patcher = patch(
            "api.validators.transaction.get_protocol_cost_models",
            return_value=COST_MODELS,
        )
        self.mock_models = self.models_patcher.start()

    def tearDown(self):
        self.models_patcher.stop()

    @patch("api.validators.transaction.evaluate_transaction")
    def test_valid_tx_passes_silently(self, mock_eval):
        # Koios accepted the tx — response includes a 'result' key.
        mock_eval.return_value = _evaluation_response([EVALUATION])
        check_valid_tx(TX_CBOR, "preprod")
        mock_eval.assert_called_once_with(TX_CBOR, "preprod")

    @patch("api.validators.transaction.evaluate_transaction")
    def test_invalid_tx_raises_validation_error(self, mock_eval):
        # A real ledger verdict. Ogmios reports transaction-domain failures
        # with its own codes in the 3000s (3161 = script went beyond its
        # allocated budget), outside JSON-RPC's reserved range.
        mock_eval.return_value = {
            "jsonrpc": "2.0",
            "method": "evaluateTransaction",
            "error": {"code": 3161, "message": "budget exceeded"},
        }
        with self.assertRaises(ValidationError) as context:
            check_valid_tx(TX_CBOR, "preprod")
        self.assertIn("Transaction Fails Validation", str(context.exception.detail))

    @patch("api.validators.transaction.evaluate_transaction")
    def test_jsonrpc_protocol_errors_are_upstream_failures_not_bad_transactions(
        self, mock_eval
    ):
        """A broken endpoint must not be reported as a broken transaction.

        JSON-RPC reserves -32768..-32000 for protocol faults. A KOIOS_URL
        pointing at a build without evaluateTransaction answers -32601 over
        HTTP 200; calling that a 400 tells every wallet its transaction is bad
        while the service is the party at fault.
        """
        for code in (-32700, -32601, -32602, -32603):
            with self.subTest(code=code):
                mock_eval.return_value = {
                    "jsonrpc": "2.0",
                    "method": "evaluateTransaction",
                    "error": {"code": code, "message": "protocol fault"},
                }
                with self.assertRaises(UpstreamServiceUnavailable):
                    check_valid_tx(TX_CBOR, "preprod")

    @patch("api.validators.transaction.evaluate_transaction")
    def test_error_without_a_numeric_code_is_an_upstream_failure(self, mock_eval):
        # Unclassifiable means "we don't know", and CLAUDE.md is explicit that
        # the unknown case must not become a caller-blaming 400.
        for error in ({"message": "no code"}, "just a string", {"code": "3161"}):
            with self.subTest(error=error):
                mock_eval.return_value = {
                    "jsonrpc": "2.0",
                    "method": "evaluateTransaction",
                    "error": error,
                }
                with self.assertRaises(UpstreamServiceUnavailable):
                    check_valid_tx(TX_CBOR, "preprod")

    @patch("api.validators.transaction.evaluate_transaction")
    def test_malformed_success_response_is_upstream_failure(self, mock_eval):
        for response in (
            None,
            [],
            {"result": []},
            {"jsonrpc": "2.0", "result": None},
            {"jsonrpc": "2.0", "result": [], "error": {}},
            {"jsonrpc": "2.0", "method": "submitTransaction", "result": []},
        ):
            with self.subTest(response=response):
                mock_eval.return_value = response
                with self.assertRaises(UpstreamServiceUnavailable):
                    check_valid_tx(TX_CBOR, "preprod")

    @patch("api.validators.transaction.evaluate_transaction")
    def test_empty_evaluation_is_not_a_collateral_transaction(self, mock_eval):
        mock_eval.return_value = _evaluation_response([])
        with self.assertRaises(ValidationError) as context:
            check_valid_tx(TX_CBOR, "preprod")
        self.assertIn("No Plutus Scripts", str(context.exception.detail))

    @patch("api.validators.transaction.evaluate_transaction")
    def test_malformed_evaluation_entry_is_upstream_failure(self, mock_eval):
        malformed = (
            {},
            {"validator": "spend:0"},
            {"validator": "spend:0", "budget": {"memory": True, "cpu": 1}},
            {"validator": "spend:0", "budget": {"memory": -1, "cpu": 1}},
        )
        for evaluation in malformed:
            with self.subTest(evaluation=evaluation):
                mock_eval.return_value = _evaluation_response([evaluation])
                with self.assertRaises(UpstreamServiceUnavailable):
                    check_valid_tx(TX_CBOR, "preprod")

    @patch("api.validators.transaction.evaluate_transaction")
    def test_upstream_failure_translates_to_503(self, mock_eval):
        # Koios was unreachable / timed out / returned junk. We must NOT
        # surface that as a 400 — the user's tx might be perfectly valid.
        mock_eval.side_effect = UpstreamUnavailable("koios preprod timed out")
        with self.assertRaises(UpstreamServiceUnavailable) as context:
            check_valid_tx(TX_CBOR, "preprod")
        self.assertEqual(context.exception.status_code, 503)
        self.assertIn(
            "Validation Service Unavailable", str(context.exception.detail)
        )

    @patch("api.validators.transaction.evaluate_transaction")
    def test_rejects_committed_budget_below_evaluated_requirement(self, mock_eval):
        zero_budget_tx = _tx_cbor(
            {(0, 0): [cbor2.CBORTag(121, []), [0, 0]]}
        )
        mock_eval.return_value = _evaluation_response(
            [
                {
                    "validator": "spend:0",
                    "budget": {"memory": 1, "cpu": 1},
                }
            ]
        )

        with self.assertRaises(ValidationError) as context:
            check_valid_tx(zero_budget_tx, "preprod")

        self.assertIn("Budget Is Too Small", str(context.exception.detail))

    @patch("api.validators.transaction.evaluate_transaction")
    def test_rejects_evaluation_pointer_mismatch(self, mock_eval):
        mock_eval.return_value = _evaluation_response(
            [
                {
                    "validator": "mint:0",
                    "budget": {"memory": 1, "cpu": 1},
                }
            ]
        )
        with self.assertRaises(UpstreamServiceUnavailable):
            check_valid_tx(TX_CBOR, "preprod")

    @patch("api.validators.transaction.evaluate_transaction")
    def test_accepts_legacy_list_redeemer_encoding(self, mock_eval):
        legacy_tx = _tx_cbor(
            [[0, 0, cbor2.CBORTag(121, []), [10, 10]]]
        )
        mock_eval.return_value = _evaluation_response([EVALUATION])
        check_valid_tx(legacy_tx, "preprod")

    @patch("api.validators.transaction.evaluate_transaction")
    def test_rejects_witness_redeemer_not_committed_by_body(self, mock_eval):
        decoded = cbor2.loads(bytes.fromhex(TX_CBOR))
        decoded[1][5][(0, 0)][0] = cbor2.CBORTag(121, [1])

        with self.assertRaises(ValidationError) as context:
            check_valid_tx(cbor2.dumps(decoded).hex(), "preprod")

        self.assertIn("Does Not Commit", str(context.exception.detail))
        mock_eval.assert_not_called()

    @patch("api.validators.transaction.evaluate_transaction")
    def test_protocol_parameters_failure_is_503_before_evaluation(self, mock_eval):
        self.mock_models.side_effect = ProtocolParametersUnavailable("unavailable")

        with self.assertRaises(UpstreamServiceUnavailable) as context:
            check_valid_tx(TX_CBOR, "preprod")

        self.assertEqual(context.exception.status_code, 503)
        mock_eval.assert_not_called()

    @patch("api.validators.transaction.evaluate_transaction")
    def test_rejects_missing_redeemers_before_evaluation(self, mock_eval):
        no_redeemers = cbor2.dumps([{}, {}, True, None]).hex()
        with self.assertRaises(ValidationError) as context:
            check_valid_tx(no_redeemers, "preprod")
        self.assertIn("No Redeemers", str(context.exception.detail))
        mock_eval.assert_not_called()
