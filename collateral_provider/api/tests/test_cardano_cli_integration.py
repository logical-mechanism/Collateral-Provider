"""Optional cross-implementation checks against the official Cardano CLI.

These tests skip on lightweight CI runners where ``cardano-cli`` is absent.
Operators and release hosts with the node tooling installed get an independent
check that our hand-rolled body-byte slicing agrees with the Cardano
implementation, rather than merely agreeing with another cbor2 round-trip.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from api.signature import tx_id
from api.tests.test_data import valid_tx_body_cbor_with_collateral


@unittest.skipUnless(shutil.which("cardano-cli"), "cardano-cli is not installed")
class CardanoCliIntegrationTest(unittest.TestCase):
    def test_transaction_id_matches_cardano_cli(self):
        tx_cbor = valid_tx_body_cbor_with_collateral()
        envelope = {
            "type": "Tx ConwayEra",
            "description": "Collateral Provider cross-implementation test vector",
            "cborHex": tx_cbor,
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tx_file:
            json.dump(envelope, tx_file)
            path = tx_file.name
        try:
            result = subprocess.run(
                [
                    "cardano-cli",
                    "latest",
                    "transaction",
                    "txid",
                    "--tx-file",
                    path,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        finally:
            os.unlink(path)

        cli_output = json.loads(result.stdout)
        self.assertEqual(cli_output["txhash"], tx_id(tx_cbor))
