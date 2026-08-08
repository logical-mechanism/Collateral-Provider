"""Direct tests for api.services.collateral.issue_witness.

These tests used to live in test_serializer.py but were exercising the
business pipeline through the serializer's per-field validator. After
the orchestration was extracted into a service, they belong here —
the serializer is now shape-only.
"""

from unittest.mock import patch

from django.conf import settings
from django.test import TestCase
from nacl.exceptions import RuntimeError as NaClRuntimeError
from rest_framework.exceptions import ValidationError

from api.services.collateral import SigningServiceUnavailable, issue_witness

from .test_big_data import invalid_tx_body_too_big
from .test_data import (
    invalid_tx_body_cbor_is_invalid_is_set,
    invalid_tx_body_cbor_is_lying,
    invalid_tx_body_cbor_missing_inputs,
    invalid_tx_body_cbor_spending_collateral,
    invalid_tx_body_missing_collateral,
    valid_tx_body_cbor_but_no_collateral,
)
from .test_views import build_happy_path_tx_cbor


class IssueWitnessTestCase(TestCase):
    def setUp(self):
        self.environment = 'preprod'
        self.env_settings = settings.ENVIRONMENTS.get(self.environment)
        self.networks = ['preprod', 'mainnet']
        self.ip_address = '127.0.0.1'

    def _call(self, tx_cbor: str) -> tuple[str, str]:
        return issue_witness(
            tx_cbor=tx_cbor,
            environment=self.environment,
            env_settings=self.env_settings,
            ip_address=self.ip_address,
            networks=self.networks,
        )

    def test_too_big(self):
        with self.assertRaises(ValidationError):
            self._call(invalid_tx_body_too_big())

    def test_missing_inputs(self):
        with self.assertRaises(ValidationError):
            self._call(invalid_tx_body_cbor_missing_inputs())

    def test_no_collateral_in_body(self):
        with self.assertRaises(ValidationError):
            self._call(valid_tx_body_cbor_but_no_collateral())

    def test_missing_collateral(self):
        with self.assertRaises(ValidationError):
            self._call(invalid_tx_body_missing_collateral())

    def test_spending_collateral(self):
        with self.assertRaises(ValidationError):
            self._call(invalid_tx_body_cbor_spending_collateral())

    def test_invalid_is_set(self):
        with self.assertRaises(ValidationError):
            self._call(invalid_tx_body_cbor_is_invalid_is_set())

    @patch("api.validators.transaction.evaluate_transaction")
    def test_lying_tx_rejected_by_upstream(self, mock_eval):
        # The "lying" fixture passes structural checks but Koios would
        # see through it. We simulate Koios returning an error verdict
        # and assert we surface it as a ValidationError.
        mock_eval.return_value = {
            "jsonrpc": "2.0",
            "method": "evaluateTransaction",
            "error": {"code": -32602},
        }
        with (
            patch(
                "api.validators.transaction.get_protocol_cost_models",
                return_value={2: (1,)},
            ),
            patch(
                "api.validators.transaction.verify_script_data_hash",
                return_value=True,
            ),
            self.assertRaises(ValidationError),
        ):
            self._call(invalid_tx_body_cbor_is_lying())

    @patch("api.services.collateral.check_valid_tx")
    @patch(
        "api.services.collateral.witness_tx_cbor",
        side_effect=ValueError("rotating key mismatch"),
    )
    def test_signing_identity_race_fails_closed_with_503(self, _mock_sign, _mock_check):
        with self.assertRaises(SigningServiceUnavailable) as context:
            self._call(build_happy_path_tx_cbor())
        self.assertEqual(context.exception.status_code, 503)

    @patch("api.services.collateral.check_valid_tx")
    @patch(
        "api.services.collateral.witness_tx_cbor",
        side_effect=NaClRuntimeError("libsodium signing failure"),
    )
    def test_signing_runtime_failure_fails_closed_with_503(
        self, _mock_sign, _mock_check
    ):
        with self.assertRaises(SigningServiceUnavailable) as context:
            self._call(build_happy_path_tx_cbor())
        self.assertEqual(context.exception.status_code, 503)
