# api/tests/test_serializers.py

from django.conf import settings
from django.test import TestCase

from api.serializers import ProvideCollateralSerializer

from .test_big_data import invalid_tx_body_too_big
from .test_data import (invalid_tx_body_cbor_is_invalid_is_set,
                        invalid_tx_body_cbor_is_lying,
                        invalid_tx_body_cbor_missing_inputs,
                        invalid_tx_body_cbor_spending_collateral,
                        invalid_tx_body_missing_collateral,
                        valid_tx_body_cbor_but_no_collateral)


class ProvideCollateralSerializerTestCase(TestCase):
    def setUp(self):
        # Set up the environment context once for all tests
        self.environment = 'preprod'
        self.env_settings = settings.ENVIRONMENTS.get(self.environment)
        self.ip_address = '',
        self.networks = ['preprod']

    def test_invalid_empty_tx_body(self):
        data = {
            'tx_body': "",
        }
        serializer = ProvideCollateralSerializer(
            data=data,
            context={
                'environment': self.environment,
                'env_settings': self.env_settings,
                'ip_address': self.ip_address,
                'networks': self.networks,
            }
        )
        self.assertFalse(serializer.is_valid())

    def test_invalid_tx_body_cbor_missing_inputs(self):
        data = {
            'tx_body': invalid_tx_body_cbor_missing_inputs(),
        }
        serializer = ProvideCollateralSerializer(
            data=data,
            context={
                'environment': self.environment,
                'env_settings': self.env_settings,
                'ip_address': self.ip_address,
                'networks': self.networks,
            }
        )
        self.assertFalse(serializer.is_valid())

    def test_valid_tx_body_cbor_but_no_collateral(self):
        data = {
            'tx_body': valid_tx_body_cbor_but_no_collateral(),
        }
        serializer = ProvideCollateralSerializer(
            data=data,
            context={
                'environment': self.environment,
                'env_settings': self.env_settings,
                'ip_address': self.ip_address,
                'networks': self.networks,
            }
        )
        self.assertFalse(serializer.is_valid())

    def test_invalid_tx_body_missing_collateral(self):
        data = {
            'tx_body': invalid_tx_body_missing_collateral(),
        }
        serializer = ProvideCollateralSerializer(
            data=data,
            context={
                'environment': self.environment,
                'env_settings': self.env_settings,
                'ip_address': self.ip_address,
                'networks': self.networks,
            }
        )
        self.assertFalse(serializer.is_valid())

    def test_invalid_tx_body_cbor_spending_collateral(self):
        data = {
            'tx_body': invalid_tx_body_cbor_spending_collateral(),
        }
        serializer = ProvideCollateralSerializer(
            data=data,
            context={
                'environment': self.environment,
                'env_settings': self.env_settings,
                'ip_address': self.ip_address,
                'networks': self.networks,
            }
        )
        self.assertFalse(serializer.is_valid())

    def test_invalid_tx_body_cbor_is_invalid_is_set(self):
        data = {
            'tx_body': invalid_tx_body_cbor_is_invalid_is_set(),
        }
        serializer = ProvideCollateralSerializer(
            data=data,
            context={
                'environment': self.environment,
                'env_settings': self.env_settings,
                'ip_address': self.ip_address,
                'networks': self.networks,
            }
        )
        self.assertFalse(serializer.is_valid())

    def test_invalid_tx_body_cbor_is_lying(self):
        data = {
            'tx_body': invalid_tx_body_cbor_is_lying(),
        }
        serializer = ProvideCollateralSerializer(
            data=data,
            context={
                'environment': self.environment,
                'env_settings': self.env_settings,
                'ip_address': self.ip_address,
                'networks': self.networks,
            }
        )
        # serializer doesn't know
        self.assertFalse(serializer.is_valid())

    def test_invalid_tx_body_too_big(self):
        data = {
            'tx_body': invalid_tx_body_too_big(),
        }
        serializer = ProvideCollateralSerializer(
            data=data,
            context={
                'environment': self.environment,
                'env_settings': self.env_settings,
                'ip_address': self.ip_address,
                'networks': self.networks,
            }
        )
        # serializer doesn't know
        self.assertFalse(serializer.is_valid())
