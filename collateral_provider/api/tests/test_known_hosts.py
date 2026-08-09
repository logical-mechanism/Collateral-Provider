import copy
import json

from django.conf import settings
from django.test import SimpleTestCase

from api.known_hosts import validate_known_hosts_registry

PUBLIC_KEY = "754c1db51aaee2e939b05b529ff5e210d8469afebcd2e487dae6f125fd500356"
PKH = "1108b97f2e199d58a0c0697d25412d0fb14d354dcd39654b9eb0dec8"


def _registry() -> dict:
    return {
        PKH: {
            "public_key": PUBLIC_KEY,
            "preprod": {
                "utxo": {"id": "ab" * 32, "idx": 0},
                "url": "https://provider.example/preprod/collateral/",
            },
        },
    }


class KnownHostsValidationTest(SimpleTestCase):
    def test_accepts_registry_contract(self):
        self.assertIsNone(validate_known_hosts_registry(_registry()))
        self.assertIsNone(validate_known_hosts_registry({}))

    def test_checked_in_registry_is_valid(self):
        with open(settings.KNOWN_HOSTS_PATH) as registry_file:
            registry = json.load(registry_file)
        self.assertIsNone(validate_known_hosts_registry(registry))

    def test_rejects_invalid_nested_provider_data(self):
        cases = {}

        invalid_pkh = _registry()
        invalid_pkh["not-a-pkh"] = invalid_pkh.pop(PKH)
        cases["pkh format"] = invalid_pkh

        missing_public_key = _registry()
        del missing_public_key[PKH]["public_key"]
        cases["missing public key"] = missing_public_key

        mismatched_public_key = _registry()
        mismatched_public_key[PKH]["public_key"] = "00" * 32
        cases["public key mismatch"] = mismatched_public_key

        missing_networks = _registry()
        del missing_networks[PKH]["preprod"]
        cases["missing networks"] = missing_networks

        invalid_txid = _registry()
        invalid_txid[PKH]["preprod"]["utxo"]["id"] = "ab"
        cases["txid"] = invalid_txid

        boolean_index = _registry()
        boolean_index[PKH]["preprod"]["utxo"]["idx"] = True
        cases["boolean index"] = boolean_index

        negative_index = _registry()
        negative_index[PKH]["preprod"]["utxo"]["idx"] = -1
        cases["negative index"] = negative_index

        insecure_url = _registry()
        insecure_url[PKH]["preprod"]["url"] = (
            "http://provider.example/preprod/collateral/"
        )
        cases["insecure URL"] = insecure_url

        wrong_network_url = _registry()
        wrong_network_url[PKH]["preprod"]["url"] = (
            "https://provider.example/mainnet/collateral/"
        )
        cases["URL network mismatch"] = wrong_network_url

        credentialed_url = _registry()
        credentialed_url[PKH]["preprod"]["url"] = (
            "https://user:pass@provider.example/preprod/collateral/"
        )
        cases["URL credentials"] = credentialed_url

        extra_network_field = _registry()
        extra_network_field[PKH]["preprod"]["enabled"] = True
        cases["unexpected network field"] = extra_network_field

        for name, registry in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_known_hosts_registry(copy.deepcopy(registry))
