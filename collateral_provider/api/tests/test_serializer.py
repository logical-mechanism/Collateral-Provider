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

    def test_additional_utxos_optional(self):
        serializer = ProvideCollateralSerializer(data={'tx': 'deadbeef'})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertNotIn('additional_utxos', serializer.validated_data)

    def test_additional_utxos_empty_list_normalized_to_none(self):
        serializer = ProvideCollateralSerializer(
            data={'tx': 'deadbeef', 'additional_utxos': []}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertIsNone(serializer.validated_data['additional_utxos'])

    def test_additional_utxos_pair_shape_required(self):
        serializer = ProvideCollateralSerializer(data={
            'tx': 'deadbeef',
            'additional_utxos': [[{'transaction': {'id': 'a' * 64}, 'index': 0}]],
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('additional_utxos', serializer.errors)

    def test_additional_utxos_inner_must_be_objects(self):
        serializer = ProvideCollateralSerializer(data={
            'tx': 'deadbeef',
            'additional_utxos': [['txin-as-string', {'address': 'addr...'}]],
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('additional_utxos', serializer.errors)

    def test_additional_utxos_size_capped(self):
        bloat = 'x' * 40_000
        serializer = ProvideCollateralSerializer(data={
            'tx': 'deadbeef',
            'additional_utxos': [
                [
                    {'transaction': {'id': 'a' * 64}, 'index': 0},
                    {'address': 'addr_test1qz...', 'memo': bloat},
                ]
            ],
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('additional_utxos', serializer.errors)
