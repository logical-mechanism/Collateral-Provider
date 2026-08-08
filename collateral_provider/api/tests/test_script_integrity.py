import unittest

import cbor2

from api.script_integrity import (
    ScriptIntegrityError,
    calculate_script_data_hash,
    encode_language_views,
    script_data_parts,
    verify_script_data_hash,
)
from api.tests.test_data import valid_tx_body_cbor_with_collateral

REDEEMER_BYTES = bytes.fromhex("a182000082d87980820a14")

# Koios epoch_params, mainnet epoch 511, PlutusV3.  Kept offline so this
# regression test never relies on the network.  The transaction fixture was
# accepted on-chain in that epoch and its body field 11 matches this model.
EPOCH_511_PLUTUS_V3 = (
    100788, 420, 1, 1, 1000, 173, 0, 1, 1000, 59957, 4, 1, 11183, 32,
    201305, 8356, 4, 16000, 100, 16000, 100, 16000, 100, 16000, 100,
    16000, 100, 16000, 100, 100, 100, 16000, 100, 94375, 32, 132994, 32,
    61462, 4, 72010, 178, 0, 1, 22151, 32, 91189, 769, 4, 2, 85848,
    123203, 7305, -900, 1716, 549, 57, 85848, 0, 1, 1, 1000, 42921, 4,
    2, 24548, 29498, 38, 1, 898148, 27279, 1, 51775, 558, 1, 39184,
    1000, 60594, 1, 141895, 32, 83150, 32, 15299, 32, 76049, 1, 13169,
    4, 22100, 10, 28999, 74, 1, 28999, 74, 1, 43285, 552, 1, 44749,
    541, 1, 33852, 32, 68246, 32, 72362, 32, 7243, 32, 7391, 32, 11546,
    32, 85848, 123203, 7305, -900, 1716, 549, 57, 85848, 0, 1, 90434,
    519, 0, 1, 74433, 32, 85848, 123203, 7305, -900, 1716, 549, 57,
    85848, 0, 1, 1, 85848, 123203, 7305, -900, 1716, 549, 57, 85848,
    0, 1, 955506, 213312, 0, 2, 270652, 22588, 4, 1457325, 64566, 4,
    20467, 1, 4, 0, 141992, 32, 100788, 420, 1, 1, 81663, 32, 59498,
    32, 20142, 32, 24588, 32, 20744, 32, 25933, 32, 24623, 32, 43053543,
    10, 53384111, 14333, 10, 43574283, 26308, 10, 16000, 100, 16000,
    100, 962335, 18, 2780678, 6, 442008, 1, 52538055, 3756, 18, 267929,
    18, 76433006, 8868, 18, 52948122, 18, 1995836, 36, 3227919, 12,
    901022, 1, 166917843, 4307, 36, 284546, 36, 158221314, 26549, 36,
    74698472, 36, 333849714, 1, 254006273, 72, 2174038, 72, 2261318,
    64571, 4, 207616, 8310, 4, 1293828, 28716, 63, 0, 1, 1006041,
    43623, 251, 0, 1,
)


def _raw_tx(
    committed_hash: bytes,
    redeemers: bytes = REDEEMER_BYTES,
    datums: bytes | None = None,
) -> str:
    body = cbor2.dumps({11: committed_hash})
    if datums is None:
        witnesses = b"\xa1\x05" + redeemers
    else:
        witnesses = b"\xa2\x04" + datums + b"\x05" + redeemers
    return (b"\x84" + body + witnesses + b"\xf5\xf6").hex()


class TestLanguageViewEncoding(unittest.TestCase):
    def test_pycardano_single_language_vectors(self):
        # Generated independently with PyCardano 0.13.2 using a RedeemerMap.
        vectors = (
            (
                {0: (1, -2, 300)},
                "a14100479f012119012cff",
                "d90ffb596608abad7398c9f529bda6d2c5903e0156a4eb13173f1f3abab5484b",
            ),
            (
                {1: (4, 5)},
                "a101820405",
                "15758bfcb99eb7bf33d7c724b27f04f2fc47a7a1ef82ca7f1b9b6b3f6299c794",
            ),
            (
                {2: (-900, 7)},
                "a1028239038307",
                "24df0ff8e5b7649b50dab9c366235e57c7883e3f302a08f2cff9db9e381b9601",
            ),
        )
        for models, expected_views, expected_hash in vectors:
            with self.subTest(models=models):
                self.assertEqual(encode_language_views(models).hex(), expected_views)
                self.assertEqual(
                    calculate_script_data_hash(REDEEMER_BYTES, b"", models).hex(),
                    expected_hash,
                )

    def test_live_pycardano_cross_check_when_installed(self):
        try:
            from pycardano import (
                CostModels,
                ExecutionUnits,
                RawPlutusData,
                RedeemerKey,
                RedeemerMap,
                RedeemerTag,
                RedeemerValue,
                script_data_hash,
            )
        except ImportError:
            self.skipTest("PyCardano is an optional development cross-check")

        redeemers = RedeemerMap(
            {
                RedeemerKey(RedeemerTag.SPEND, 0): RedeemerValue(
                    RawPlutusData(cbor2.CBORTag(121, [])),
                    ExecutionUnits(mem=10, steps=20),
                )
            }
        )
        for language, costs in ((0, (1, -2, 300)), (1, (4, 5)), (2, (-900, 7))):
            with self.subTest(language=language):
                models = CostModels({language: dict(enumerate(costs))})
                self.assertEqual(
                    encode_language_views({language: costs}),
                    models.to_cbor(),
                )
                self.assertEqual(
                    calculate_script_data_hash(REDEEMER_BYTES, b"", {language: costs}),
                    bytes(script_data_hash(redeemers, [], models)),
                )

    def test_mixed_models_use_ledger_shortlex_order(self):
        models = {0: (1,), 1: (2,), 2: (3,)}
        self.assertEqual(
            encode_language_views(models).hex(),
            "a30181020281034100439f01ff",
        )
        self.assertEqual(
            calculate_script_data_hash(REDEEMER_BYTES, b"", models).hex(),
            "0073264c2b07c0e1dca8da819ba6cf9e43f181ca6acfc3a4d1306469c5423ffd",
        )


class TestScriptDataBinding(unittest.TestCase):
    def test_real_accepted_mainnet_transaction_matches_historical_model(self):
        self.assertTrue(
            verify_script_data_hash(
                valid_tx_body_cbor_with_collateral(),
                {2: EPOCH_511_PLUTUS_V3},
            )
        )

    def test_exact_indefinite_redeemer_bytes_are_preserved_and_bound(self):
        redeemers = bytes.fromhex("9f9f0000d87980820a14ffff")
        models = {1: (4, 5)}
        committed = calculate_script_data_hash(redeemers, b"", models)
        tx = _raw_tx(committed, redeemers)

        body_hash, extracted_redeemers, datums = script_data_parts(tx)
        self.assertEqual(body_hash, committed)
        self.assertEqual(extracted_redeemers, redeemers)
        self.assertEqual(datums, b"")
        self.assertTrue(verify_script_data_hash(tx, models))

    def test_redeemer_mutation_does_not_match_signed_body(self):
        models = {1: (4, 5)}
        committed = calculate_script_data_hash(REDEEMER_BYTES, b"", models)
        mutated = REDEEMER_BYTES[:-1] + b"\x15"
        self.assertFalse(verify_script_data_hash(_raw_tx(committed, mutated), models))

    def test_datum_original_bytes_are_bound(self):
        datums = bytes.fromhex("81d8799f01ff")
        models = {1: (4, 5)}
        committed = calculate_script_data_hash(REDEEMER_BYTES, datums, models)
        self.assertEqual(
            committed.hex(),
            "b93bbe905b370f6d62ee0f95c5b54a7ead5a3a47c436363f361b90d9dc765e2f",
        )
        self.assertTrue(verify_script_data_hash(_raw_tx(committed, datums=datums), models))
        mutated_datums = bytes.fromhex("81d8799f02ff")
        self.assertFalse(
            verify_script_data_hash(_raw_tx(committed, datums=mutated_datums), models)
        )

    def test_present_but_empty_datum_set_contributes_no_bytes(self):
        empty_set = bytes.fromhex("d9010280")
        models = {1: (4, 5)}
        committed = calculate_script_data_hash(REDEEMER_BYTES, b"", models)
        tx = _raw_tx(committed, datums=empty_set)
        self.assertEqual(script_data_parts(tx)[2], b"")
        self.assertTrue(verify_script_data_hash(tx, models))

    def test_missing_or_malformed_body_hash_is_rejected(self):
        no_hash = cbor2.dumps([{}, {5: {}}, True, None]).hex()
        short_hash = cbor2.dumps([{11: b"short"}, {5: {}}, True, None]).hex()
        for tx in (no_hash, short_hash):
            with self.subTest(tx=tx), self.assertRaises(ScriptIntegrityError):
                script_data_parts(tx)

    def test_trailing_data_and_duplicate_redeemer_key_are_rejected(self):
        committed = bytes(32)
        trailing = _raw_tx(committed) + "00"
        duplicate_witness_key = (
            b"\x84"
            + cbor2.dumps({11: committed})
            + b"\xa2\x05"
            + REDEEMER_BYTES
            + b"\x05"
            + REDEEMER_BYTES
            + b"\xf5\xf6"
        ).hex()
        for tx in (trailing, duplicate_witness_key):
            with self.subTest(tx=tx), self.assertRaises(ScriptIntegrityError):
                script_data_parts(tx)
