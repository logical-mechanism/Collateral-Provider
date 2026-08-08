import os
import tempfile
import time
from io import BytesIO

import cbor2
from django.test import TestCase

from api.signature import (
    _clear_key_cache,
    create_witness_cbor,
    get_key_from_file,
    sign,
    tx_id,
    validate_key_material,
    verify,
    witness_tx_cbor,
)
from api.tests.test_data import (
    invalid_tx_body_missing_collateral,
    valid_tx_body_cbor_with_collateral,
)


class SignatureTestCase(TestCase):

    def test_body_hash_does_not_bind_outer_validity_or_witnesses(self):
        """Document the ledger boundary behind the collateral policy.

        Vkey witnesses sign the body only. The outer phase-2 validity flag
        and witness set may change without changing the transaction id; the
        ledger, not this signature, enforces that the flag matches script
        evaluation.
        """
        original = valid_tx_body_cbor_with_collateral()
        original_bytes = bytes.fromhex(original)
        decoded = cbor2.loads(original_bytes)
        stream = BytesIO(original_bytes)
        self.assertEqual(stream.read(1), b"\x84")
        body_start = stream.tell()
        cbor2.CBORDecoder(stream).decode()
        body_bytes = original_bytes[body_start : stream.tell()]

        changed_validity = (
            b"\x84"
            + body_bytes
            + cbor2.dumps(decoded[1])
            + cbor2.dumps(not decoded[2])
            + cbor2.dumps(decoded[3])
        ).hex()
        self.assertEqual(tx_id(original), tx_id(changed_validity))

        changed_witnesses = (
            b"\x84"
            + body_bytes
            + cbor2.dumps({0: [[bytes(32), bytes(64)]]})
            + cbor2.dumps(decoded[2])
            + cbor2.dumps(decoded[3])
        ).hex()
        self.assertEqual(tx_id(original), tx_id(changed_witnesses))

    def test_verify_works_on_good_signature(self):
        pk = "7EE70C8FF8CABD12E8453C942D65D5D5B504CC658028981F5EC16664D7B0ACBD"
        sig = "5D2190A2D12B4C7516A3D9479F860A8B68E988BA31318AB79B39ADD15E128AAF9385BDA3D7A9379DBA86A1A9092CED6B96350B1BDC0842DC93FDE785B71E6E07"
        msg = "f620a4e949bfbefbf2892d39d0777439f3acfbf850eae9b007c6558ba8ef4db4"
        outcome = verify(pk, sig, msg)
        self.assertTrue(outcome)


    def test_sign_then_verify(self):
        sk = "abffdc040fd4c5d3eb6ce962a968f57995edfb33c78a11a466446a649f3ed82c"
        pk = "51c20cf4a8ed0e13cd65026625fe59d7ee8f8ef274a3d5575f8c30f9732cb3ed"
        msg = "acab"
        sig = sign(sk, msg)
        outcome = verify(pk, sig, msg)
        self.assertTrue(outcome)
    
    def test_tx_to_tx_id1(self):
        outcome = tx_id(valid_tx_body_cbor_with_collateral())
        tx_hash = "671476c0d87cc6061597c9c6b536e8ebdf7c071188966d16af11d00ca85bef45"
        self.assertEqual(outcome, tx_hash)
    
    def test_tx_to_tx_id2(self):
        outcome = tx_id(invalid_tx_body_missing_collateral())
        tx_hash = "6788a8ef5b561ea475d81cd97ec90cfdbc1508ee7d425c3f800fcdd6de5b5b7a"
        self.assertEqual(outcome, tx_hash)

    def test_tx_id_matches_chain_for_real_submitted_tx(self):
        # Two real txs that were accepted by the chain, paired with the
        # tx-id the chain assigned. tx_id() must produce the same hash —
        # otherwise our witness signs a hash the chain disagrees with
        # and submission fails with "invalidSignatories". This is the
        # only assertion that proves the algorithm matches the chain;
        # the synthetic fixtures above only prove it stays consistent
        # with itself across refactors.
        cases = [
            (
                # mainnet, 3.1 KiB body, indefinite-length encodings inside Plutus datum
                "84aa00d9010281825820e4d20dca46f31c227666ee477770304a4f805cb2e00a4e379d243fbbc0c9d184000dd90102818258208a6bed6b72cfe64fb8e9531badf2cd6d199a2fcd9120057d29711fcf5f8fab150212d90102818258206eabeeda6895cf81bcf2c4feba255a6981e9d02506b8e00c46dbc9347d31b00f010182a300581d700ee28a6d25ddab3f6ec2e71334f36cbd85e2530b104dbddb92e865e501821a00bcf1a6a1581c21b5bcf6f42eeac1b00121579e1a490134b08510120be94b5c3a0c86a1582000e4d20dca46f31c227666ee477770304a4f805cb2e00a4e379d243fbbc0c9d101028201d818590a26d8799f581c0ee28a6d25ddab3f6ec2e71334f36cbd85e2530b104dbddb92e865e5581c222e249ab3df32ab0f984ef1cb84d765af62b76b86a92ce12d77f31f581c4354497e77eac590093c0556cca9aac43616314b883ecc3b306f5322581c495cb46f90fd58b44eccc99b160ea4182ef17df44cb7deac48040ebad8799f182558308f9a7bae3a1e87b9fac96baee301945cc1fc70f4ecf30b72792152e6eb8a6777c1adcffc6190e7a0ba5034cff589e16a5f584083b22bc12365ee725a5aad48acc74bf63a517f1032703c8f5c52195146372adae1ec1a43a049791a08781f4ced01b2fd07e179cb1afa0cfdf96d6660049f82585820e8639948e8f478166be1142c5ed93c90b1bc273ca390c13e2c7ee7add7bbf7e9ff5f584093e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc510515820c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8ff5f5840b89093b5e68d0f7b95e1bb06712c37befe433e0550cb25e7172ec538b5fa5bce72f70742bcf531e4140d978daf1388cc019818a8312f7d2385ae83d3373538f7582032071ec7d7768b5ae71e21eeb91b088cb2c39d3078a15b15a41bfad016d590feff9f58309034c0e6bf1500b6b5109afa89c45c654deae9f244ed534756c06dcf9e3a7745a82a60dd5c7e7ffaec671a579d295c9c5830930357dea42061f4955c243ab767d74d827e471a2ffb18133fe865895b3ba8be0333a18142e2565e516d9e4e5890402958308316d8926a657be5172f2a7406adbd4d19c18f26d53d9cf245e5b821c3d80d58d93f742c191a359873d84e3e4b28ab22583084c1e64131112181c5fa24e7e15dd382bf089f7632436556c5616436fd687ee06ac53e7126b940d1d8aa0e8da3d3ee7e583084dd02d103e1a92c00fb5f4f313b8b0666e3e05886a798792b9dd6a638dcf5bfeb58e662e608c62e544573dbd0432be2583080efead39c1a5b517741bb22e4e3a15d422bed7717490362445d921f18faf4236b0ac764ed11c334293cb789b354bc8b583089a5c772103515212c0ad9b447d55795b05d1a905cef0731b7cecf7fceb4f90f95373556d2b5c1afd346a8a0685d9d465830b5f18397e0212435bd883220a16cedaf1f8de38d3ed49272887be70a9595f0233aa3fd4e34a196710cf2abb7c73062f6583095656039cb8fbe76dff2742aab2968cd5766110444c590a3e9dc4440960f106214ba4c0a965ed35278c07993c69d45455830851869167ec4e80b3828c03d0ea65e806c504f70bff128df1ce6f7a8e4353eea51821b42b263c1505c998dbe77bc36415830a67f20dcbe3a9cc31c38b634656d2b5894a08c8f13391877c52124daff1fd0239cdbed6221386e4b6fd444ca8ace14775830b577d73a73bc5a80930dda1ae1dda744e97d97d1d9e041f4e442be6c327928122a579f128b213f10ce4eb6652f4918f95830ace90e50756a9a3c3100dee14a0a107d43ea60856ce1e74e6dddf57ddcfcd6b3a4ec5ce54c089873ecc11a4e4bd8f57b58308a5e43f72debaee6e7f987f5ea99119051d22beb7856cf12334fbfdba215b8ecf81763999b44edcb0f03225606f486375830a7112c7d1e8d5a26e68f3cc4ece1e98bbe1f5118ae578d1d92ec54c086274321c8ce1e39faa5c9af2676a192f4f77a80583089c494cb71f7dae7809aba86595716cb3414a91771d7ef4741026bc011fc2be447a4916aff2f53bc68441ccdc5fa88125830a1bbcfe36ef67e38e74b208813b341ac1223ae1343e5595313fe2b0d4fffe4739207f83b57a345f3c46860c2988e89825830882f14c0b56ef12e8a5881a3b6b263967b86d218e35fb17657eb90b6b8ed8eb4ba6d4bc2d4a28843a4d87441052121f45830a9b04b988a256e62a69c751574b7251986576684a9686385d4697b1b78dbcb1ed15bd22a77ad86cdb7a1e939324e7ed558308f2a04759d63a4d75bff862fe9fb4906291597abf98c9966f4cbc383b8404bd457577566b4518e98f97c0e7b7f9f819058309451b1e07ca7bce0e338889ff6458249e541635cf5037bca7c4e38dd9965f6f3051e3ae6126f5943ffe1d3f00903e05858308b6857d9663f6d82aa9ba847a6970fd8193243b0143404d89f7b021b5e1376fe7c625f4d89461023a30c6895c3af431258308f74a1dfad802b6af3fd57334b4e2d2ec75dfdb1418504618e8ec85f93d6d681e9c00cd1b5244607efe7bf4d99ed4f8f5830b5a40db6ec975fb713b3793ef05ed2fb5e40ee126707b5006cc479bbd5547b8c8631ca668c2e95b8a1f9e559a232f3e15830b93ed02bd864e0cf2b3466b4fd9b60cda5ab73adcf4a1a9a0aabdb9d34789451aee2758076b4a97ab50d48b9a644859a58308f731c0e221a59d899d5a8b01df84d3c383d3ea8f30c48c19860a5db49d72e2c5925bd3bd277b03ad35ecd6a892e07d25830a526ac6fca866493af15127330d65807e5fa6097b6df5120dfb41d52b5613c8efe6b1bc412ec456cd2099c3356ab99955830812e232d45eda12e489d183e8cf298c9a032dfbce2ab4906ce05555a06e80494caa36102f3a304df1bfa820b2ce283165830a0afd7cf663b1fdf1c6b1fb27e11c3fd4174b20db82e679e29ac0959f94897b16e1bec6a59c481ab6a850883db9102fb5830852ce127b66c0722188278957b81377dea12b0e19c918ad1639ed65861ee4a1055dd76e6aade9cc1969c2532db3c28e85830b484f2124a4e6530e95856e605e7dc7691436e7fd8e388bdbc53dc2c1a8153a2412b93a8fcd6be5b026b488229d24a66583098d0d317c06e95c66425e5d5dc96ecdecfe1f9c379f43c32e91e6e622dce993746071eadf95506b4adfe5028a455080e5830b745b17c5aa144c82228542e89d883dff1046267dd6befdff3ffe75bbe26a8663bf4c6777463f193b9b803f8b31a26945830b87da441a37b7c4b63f576e44e4ac802e12763c8e03e76e56c25c28809021e1399dc024a8d14fbeb44887d9009e8789a5830a6c558ce9419f54a15a6fbea7b91c2ba9d2f20a1ed0b1536a6f238c9b318e2e165f03f525e9747eb2b8756c4f12462355830a4cfe9f8ac1c3b6d79286be720b5a49f5c9c29eb3115283d77c93ba738e3c7a8c7c1ffc34df2d27c9292d1c120ea3cda5830a2710e18ea203e41515dbd6b7120149b70a80a632036df4d215bb0d812e2cc4f9d0e1b24a55fb582e90fdfc76217486d583087ffd9dd456e747d0a789ba308073085b08f54e6c865b2508b206cb8b085f5368a52ae33c0c00fc6df3726f9f0d75d50ff9fd8799f5f584093e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc510515820c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8ff5f5840a8a277aa6084d9b6c398439201484885af7dc1d8dd9547b4dc398b127f7b5c8f4dabd9e5e0ddf37917326d8ec46a5a98055750730b28b047a370a9f95994be1c582099820863105d614f5975a559f0184c75af99971ff84d1925822bf4b439ad63b4ffffffffff82583900dd996ca1174aa2e32dbbad88046b440ff563a3cde0716a56865400c6b5c562bdedfb6d283af13b35a63556c0d4acc5ea01069f96e7975a6b1a006e766a1082583900dd996ca1174aa2e32dbbad88046b440ff563a3cde0716a56865400c6b5c562bdedfb6d283af13b35a63556c0d4acc5ea01069f96e7975a6b1a0043a3d8111a0008a768021a0005c4f00ed9010282581c01e7fe6f0fb975d8e24076a36e491f36896a441c4598cbd88b517056581cc47aa4f225e3492f3d9a944489c1c78b3c4637908fcb5805ce04470209a1581c21b5bcf6f42eeac1b00121579e1a490134b08510120be94b5c3a0c86a1582000e4d20dca46f31c227666ee477770304a4f805cb2e00a4e379d243fbbc0c9d1010b5820d065a575eaed34c493efdd2c81592822fb33062ca6bb527c898ab77a8a3c83e1a200d9010282825820df22bae75442283e8ceb2714d1b65d77449f9ebe3f1033d0362183720891d6ef58404b1d74e0eb8fa29de622fc57c50b8cf0afdc6feac373d4852d0a34c5f7e468e7a97efa130e39a29acc067f3700554d4d5267a6ea607367491ac38b9e62ecd20e825820ddb67b71cf203e03e7adeef4c97e945d5110abc7b638daa2a5def5961f8e9b4f5840cce1b4852f5801b6be3c632e29e20e087239316db9e346bad7c4f462152d152da4bf12f4d0294a5ab5346060abd154e09be0834cc6e8422be2587448de2fdc0405a182010082d87980821a0004d14b1a05938f1af5f6",
                "b261a8123265a19cdb5c33db7f0afead6e92b93d747b3deaec3b8e0c0ae6d1c2",
            ),
            (
                # small body with Plutus script in outputs
                "84a300d9010281825820613ef2c284082d666d6a9b0b309437b10d1099eaca46134f77828294ad21347600018282581d60fdd320cd9c529f021452b5b39eb3a6d854f3d1d59c329d2ed1b803951a0be79cc9a300581d60fdd320cd9c529f021452b5b39eb3a6d854f3d1d59c329d2ed1b80395011a001822ca03d81858a38203589f589d010100332229800ab9cab9a9bae0039bae0024888966002a66008921104920616c77617973206661696c203a2f00168a4d15330044911856616c696461746f722072657475726e65642066616c73650013656400c4c11e581c21b5bcf6f42eeac1b00121579e1a490134b08510120be94b5c3a0c86004c0122582000e4d20dca46f31c227666ee477770304a4f805cb2e00a4e379d243fbbc0c9d10001021a0003bf3ba100d90102818258207668cfa9f6d2de5b4b86de0dc291f26574c93a9e57bd7e6a634fdb85fe19518458401bf79ba1e08f6e1546f58f82ab04991924acfd45323656f24a390b34d232e6319657187872e55d8751a51c31390b621a60ce868a3957050bab5325581d947f0ef5f6",
                "d633980cd09ed263782161381de7a48a6c5814ddfff0b2eef4999e851c13ce70",
            ),
        ]
        for tx_hex, expected in cases:
            self.assertEqual(tx_id(tx_hex), expected)
    
    def test_create_proper_witness(self):
        pk = "FA2025E788FAE01CE10DEFFFF386F992F62A311758819E4E3792887396C171BA"
        sig = "F79613A21B87E80F8FFF4FA6E878C58186381BA10C46F7B4569A9183EF9FD077AD844F88DDBBE9285FAA9FEBBF3EACBB41338B9889FF82B6252139279FB53C07"
        outcome = create_witness_cbor(pk, sig)
        witness_cbor = "8200825820fa2025e788fae01ce10deffff386f992f62a311758819e4e3792887396c171ba5840f79613a21b87e80f8fff4fa6e878c58186381ba10c46f7b4569a9183ef9fd077ad844f88ddbbe9285faa9febbf3eacbb41338b9889ff82b6252139279fb53c07"
        self.assertEqual(outcome, witness_cbor)
    
    def test_creating_a_witness(self):
        tx_hash = tx_id(valid_tx_body_cbor_with_collateral())
        sk = "abffdc040fd4c5d3eb6ce962a968f57995edfb33c78a11a466446a649f3ed82c"
        pk = "51c20cf4a8ed0e13cd65026625fe59d7ee8f8ef274a3d5575f8c30f9732cb3ed"
        sig = sign(sk, tx_hash)
        witness_cbor = create_witness_cbor(pk, sig)
        answer = "820082582051c20cf4a8ed0e13cd65026625fe59d7ee8f8ef274a3d5575f8c30f9732cb3ed584077589916b53ea6abfb4e9793770bf5fbb0bbe153046e12b91365832f2c1558aec34dcf8544b15fbdd1946b32b10b38dfa70defaeb827d98a4f959539000df502"
        self.assertEqual(witness_cbor, answer)


class GetKeyFromFileTestCase(TestCase):
    def setUp(self):
        _clear_key_cache()

    def _key_files(self, skey_hex, vkey_hex):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".skey", delete=False) as skey:
            skey.write('{"cborHex":"5820' + skey_hex + '"}')
        with tempfile.NamedTemporaryFile(mode="w", suffix=".vkey", delete=False) as vkey:
            vkey.write('{"cborHex":"5820' + vkey_hex + '"}')
        self.addCleanup(os.unlink, skey.name)
        self.addCleanup(os.unlink, vkey.name)
        return skey.name, vkey.name

    def _atomic_replace_key(self, path: str, value: str, mtime_ns: int) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".key",
            dir=os.path.dirname(path),
            delete=False,
        ) as replacement:
            replacement.write('{"cborHex":"5820' + value + '"}')
            replacement_path = replacement.name
        try:
            os.utime(replacement_path, ns=(mtime_ns, mtime_ns))
            os.replace(replacement_path, path)
        finally:
            if os.path.exists(replacement_path):
                os.unlink(replacement_path)

    def test_validates_consistent_signing_identity(self):
        skey = "00" * 32
        vkey = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        pkh = "cb9358529df4729c3246a2a033cb9821abbfd16de4888005904abc41"
        paths = self._key_files(skey, vkey)
        validate_key_material(*paths, pkh)

    def test_rejects_vkey_that_does_not_match_skey(self):
        paths = self._key_files("00" * 32, "00" * 32)
        with self.assertRaisesRegex(ValueError, "does not match signing key"):
            validate_key_material(*paths, "00" * 28)

    def test_rejects_pkh_that_does_not_match_vkey(self):
        vkey = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        paths = self._key_files("00" * 32, vkey)
        with self.assertRaisesRegex(ValueError, "PKH does not match"):
            validate_key_material(*paths, "00" * 28)

    def test_witness_derives_public_key_from_signing_key_and_checks_pkh(self):
        skey = "00" * 32
        vkey = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        pkh = "cb9358529df4729c3246a2a033cb9821abbfd16de4888005904abc41"
        skey_path, _ = self._key_files(skey, vkey)

        witness, _ = witness_tx_cbor(
            valid_tx_body_cbor_with_collateral(), skey_path, pkh
        )
        decoded = cbor2.loads(bytes.fromhex(witness))
        self.assertEqual(decoded[1][0].hex(), vkey)

        with self.assertRaisesRegex(ValueError, "does not match configured PKH"):
            witness_tx_cbor(
                valid_tx_body_cbor_with_collateral(), skey_path, "00" * 28
            )

    def test_strips_cbor_tag_prefix(self):
        # 5820 is the CBOR tag for "byte string of length 32" — the leading 4
        # hex chars in the cborHex value. The rest is the raw key material.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".skey", delete=False) as f:
            f.write('{"cborHex": "5820' + "ab" * 32 + '"}')
            path = f.name
        try:
            key = get_key_from_file(path)
            self.assertEqual(key, "ab" * 32)
            self.assertEqual(len(key), 64)
        finally:
            os.unlink(path)

    def test_missing_file_raises_oserror(self):
        with self.assertRaises(OSError):
            get_key_from_file("/nonexistent/path/payment.skey")

    def test_caches_when_mtime_unchanged(self):
        # The hot path must avoid re-opening + json-decoding the skey on
        # every signing request. We assert this by writing different content
        # to the file but holding mtime constant — the cache should still
        # serve the original value.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".skey", delete=False) as f:
            f.write('{"cborHex": "5820' + "cd" * 32 + '"}')
            path = f.name
        try:
            first = get_key_from_file(path)
            stat_before = os.stat(path)
            with open(path, "w") as f:
                f.write('{"cborHex": "5820' + "ef" * 32 + '"}')
            os.utime(path, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
            second = get_key_from_file(path)
            self.assertEqual(first, second)
        finally:
            os.unlink(path)

    def test_reloads_when_mtime_advances(self):
        # An operator rotating keys (atomic write-tmp + rename) should see
        # the new key picked up on the next signing request, without a
        # service restart.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".skey", delete=False) as f:
            f.write('{"cborHex": "5820' + "11" * 32 + '"}')
            path = f.name
        try:
            first = get_key_from_file(path)
            self.assertEqual(first, "11" * 32)

            time.sleep(0.01)  # ensure a noticeable mtime tick
            with open(path, "w") as f:
                f.write('{"cborHex": "5820' + "22" * 32 + '"}')
            now = time.time()
            os.utime(path, (now, now))

            second = get_key_from_file(path)
            self.assertEqual(second, "22" * 32)
            self.assertNotEqual(first, second)
        finally:
            os.unlink(path)

    def test_reloads_equal_mtime_atomic_replacement(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".skey", delete=False) as f:
            f.write('{"cborHex": "5820' + "11" * 32 + '"}')
            path = f.name
        try:
            self.assertEqual(get_key_from_file(path), "11" * 32)
            original = os.stat(path)

            self._atomic_replace_key(path, "22" * 32, original.st_mtime_ns)

            replacement = os.stat(path)
            self.assertNotEqual(replacement.st_ino, original.st_ino)
            self.assertEqual(replacement.st_mtime_ns, original.st_mtime_ns)
            self.assertEqual(get_key_from_file(path), "22" * 32)
        finally:
            os.unlink(path)

    def test_reloads_older_mtime_atomic_replacement(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".skey", delete=False) as f:
            f.write('{"cborHex": "5820' + "11" * 32 + '"}')
            path = f.name
        try:
            self.assertEqual(get_key_from_file(path), "11" * 32)
            original = os.stat(path)
            older_mtime_ns = max(0, original.st_mtime_ns - 1_000_000_000)

            self._atomic_replace_key(path, "22" * 32, older_mtime_ns)

            self.assertLessEqual(os.stat(path).st_mtime_ns, original.st_mtime_ns)
            self.assertEqual(get_key_from_file(path), "22" * 32)
        finally:
            os.unlink(path)
