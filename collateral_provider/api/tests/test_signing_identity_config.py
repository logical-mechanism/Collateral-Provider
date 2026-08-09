"""Pin the canonicalization of operator-supplied identity values.

``bytes.fromhex`` tolerates uppercase hex and silently skips ASCII whitespace,
so startup validation and ``/healthz`` both accepted ``PKH=CB93...`` and
``PKH=' cb93...\\n'``. Every request-time comparison is an exact lowercase
string match instead — ``check_signers`` compares against ``signer.hex()`` and
``check_collateral`` against ``utxo[0].hex()``. The result was a service that
reported itself healthy and then rejected 100% of transactions with a message
blaming the caller.
"""

from collateral_provider.settings import _canonical_hex
from django.test import SimpleTestCase


class CanonicalHexTestCase(SimpleTestCase):
    PKH = "cb9358529df4729c3246a2a033cb9821abbfd16de4888005904abc41"

    def test_uppercase_is_lowercased(self):
        self.assertEqual(_canonical_hex(self.PKH.upper(), "PKH", 28), self.PKH)

    def test_surrounding_and_internal_whitespace_is_stripped(self):
        for raw in (f"  {self.PKH}  ", f"{self.PKH}\n", f"\t{self.PKH}"):
            with self.subTest(raw=raw):
                self.assertEqual(_canonical_hex(raw, "PKH", 28), self.PKH)

    def test_already_canonical_value_is_unchanged(self):
        self.assertEqual(_canonical_hex(self.PKH, "PKH", 28), self.PKH)

    def test_non_hex_refuses_to_start(self):
        with self.assertRaises(RuntimeError) as context:
            _canonical_hex("nothex", "PKH", 28)
        self.assertIn("PKH must be hexadecimal", str(context.exception))

    def test_wrong_length_refuses_to_start(self):
        with self.assertRaises(RuntimeError) as context:
            _canonical_hex("ab" * 27, "PKH", 28)
        self.assertIn("exactly 28 bytes", str(context.exception))

    def test_length_is_optional_so_dev_can_leave_a_network_blank(self):
        # apps.py enforces the 32-byte TXID rule for every non-development
        # environment; settings deliberately does not, so a local setup can
        # configure preprod and leave mainnet empty.
        self.assertEqual(_canonical_hex("", "MAINNET_TXID"), "")

    def test_canonicalized_pkh_matches_what_validators_compare_against(self):
        """The whole point: settings output must equal ``bytes.hex()``."""
        canonical = _canonical_hex(self.PKH.upper(), "PKH", 28)
        self.assertEqual(bytes.fromhex(canonical).hex(), canonical)
