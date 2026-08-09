"""Shape-only tests for ProvideCollateralSerializer.

Pipeline-level tests (CBOR validity, collateral-usage rules, signer
checks, upstream evaluation) live in test_services.py because they
exercise api.services.collateral.issue_witness, not the serializer.
"""

from django.test import TestCase

from api.serializers import ProvideCollateralSerializer


class ProvideCollateralSerializerShapeTestCase(TestCase):
    def test_empty_tx_rejected(self):
        serializer = ProvideCollateralSerializer(data={'tx': ''})
        self.assertFalse(serializer.is_valid())
        self.assertIn('tx', serializer.errors)

    def test_missing_tx_rejected(self):
        serializer = ProvideCollateralSerializer(data={})
        self.assertFalse(serializer.is_valid())
        self.assertIn('tx', serializer.errors)

    def test_wellformed_request_passes_shape_check(self):
        # Even a hex string that won't decode passes the *shape* check —
        # the serializer's job is structural, not semantic.
        serializer = ProvideCollateralSerializer(data={'tx': 'deadbeef'})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data['tx'], 'deadbeef')

    def test_additional_utxos_may_be_omitted(self):
        serializer = ProvideCollateralSerializer(data={'tx': 'deadbeef'})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertNotIn('additional_utxos', serializer.validated_data)

    def test_empty_additional_utxos_is_accepted_for_compatibility(self):
        serializer = ProvideCollateralSerializer(
            data={'tx': 'deadbeef', 'additional_utxos': []}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertIsNone(serializer.validated_data['additional_utxos'])

    def test_non_empty_additional_utxos_is_always_rejected(self):
        serializer = ProvideCollateralSerializer(data={
            'tx': 'deadbeef',
            'additional_utxos': [
                [
                    {'transaction': {'id': 'a' * 64}, 'index': 0},
                    {'address': 'addr_test1...'},
                ]
            ],
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('not supported', str(serializer.errors))
