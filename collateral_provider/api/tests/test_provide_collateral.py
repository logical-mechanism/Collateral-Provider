# api/tests.py
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from .test_data import (invalid_tx_body_cbor_is_lying,
                        invalid_tx_body_cbor_missing_inputs,
                        invalid_tx_body_cbor_spending_collateral,
                        invalid_tx_body_missing_collateral,
                        valid_tx_body_cbor_but_no_collateral)


class ProvideCollateralTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.environment = 'preprod'  # Specify the environment
        self.url = reverse('collateral', kwargs={'environment': self.environment})

    def tearDown(self):
        # Clear the cache after each test
        cache.clear()

    def test_valid_tx_body_cbor_but_no_collateral(self):
        data = {
            'tx_body': valid_tx_body_cbor_but_no_collateral(),
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, 400)

    def test_invalid_tx_body_cbor_missing_inputs(self):
        data = {
            'tx_body': invalid_tx_body_cbor_missing_inputs(),
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, 400)

    def test_invalid_tx_body_missing_collateral(self):
        data = {
            'tx_body': invalid_tx_body_missing_collateral(),
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, 400)

    def test_invalid_tx_body_cbor_spending_collateral(self):
        data = {
            'tx_body': invalid_tx_body_cbor_spending_collateral(),
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, 400)

    def test_invalid_tx_body_cbor_is_lying(self):
        data = {
            'tx_body': invalid_tx_body_cbor_is_lying(),
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, 400)
