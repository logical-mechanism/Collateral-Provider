# api/tests.py
from django.test import TestCase
from api.signature import verify, sign, tx_id, witness
from api.tests.test_data import valid_tx_body_cbor_with_collateral, invalid_tx_body_missing_collateral

class SignatureTestCase(TestCase):

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

    def test_tx_must_be_ordered_sets(self):
        outcome = tx_id("84a900d9010282825820b64bad0c2dccb1cbbe3e2c403bdd23cf386d99b5189eb497706618effe0fa2c000825820b64bad0c2dccb1cbbe3e2c403bdd23cf386d99b5189eb497706618effe0fa2c0010dd90102818258201d388e615da2dca607e28f704130d04e39da6f251d551d66d054b75607e0393f0012d90102828258205c56845e7a7f41adb63368fa76a26cd14d3c90202ce077e916f2adc7bde143ba01825820b9050d8cbc66911b3ce92eb0c802fd8ff9feabc1f22f905bc196af97c89ec730010182a300581d709199af82ef100e84dcd7ab1af3d75fe02da6b948d0870ad71e825807011a0027534e028201d818582bd8799f5820005af54f924542c59a377807c358ef840e0b4667081a6ef8018cdba71079c64a1a000445c0ffa300581d708197322941ed4206c58164f8b9cf489ab8894cb6a51814651656e00801821a0016080aa1581c8197322941ed4206c58164f8b9cf489ab8894cb6a51814651656e008a15820005af54f924542c59a377807c358ef840e0b4667081a6ef8018cdba71079c64a01028201d818583dd8799f1b00000194ed27dc001b0000019506e7a8001a19bfcc005820005af54f924542c59a377807c358ef840e0b4667081a6ef8018cdba71079c64aff021a00042aa8031a04fd8601081a04fd83a80ed9010281581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f40b5820569aabd5f45aef3502899211e4c69ec4d5b5d899790723da478c3471c722e356a200d9010281825820fa2025e788fae01ce10deffff386f992f62a311758819e4e3792887396c171ba5840f79613a21b87e80f8fff4fa6e878c58186381ba10c46f7b4569a9183ef9fd077ad844f88ddbbe9285faa9febbf3eacbb41338b9889ff82b6252139279fb53c0705a282000082d87a80821a000277a01a039a534f82000182d87980821a0002d44c1a03cb0ea6f5f6")
        tx_hash = "75c7489e665f8e225a70444caa5a671e991fd5f0f2a96ee707c98e6e66147d90"
        self.assertEqual(outcome, tx_hash)
    
    def test_create_proper_witness(self):
        pk = "FA2025E788FAE01CE10DEFFFF386F992F62A311758819E4E3792887396C171BA"
        sig = "F79613A21B87E80F8FFF4FA6E878C58186381BA10C46F7B4569A9183EF9FD077AD844F88DDBBE9285FAA9FEBBF3EACBB41338B9889FF82B6252139279FB53C07"
        outcome = witness(pk, sig)
        witness_cbor = "8200825820fa2025e788fae01ce10deffff386f992f62a311758819e4e3792887396c171ba5840f79613a21b87e80f8fff4fa6e878c58186381ba10c46f7b4569a9183ef9fd077ad844f88ddbbe9285faa9febbf3eacbb41338b9889ff82b6252139279fb53c07"
        self.assertEqual(outcome, witness_cbor)
    
    def test_creating_a_witness(self):
        tx_hash = tx_id(valid_tx_body_cbor_with_collateral())
        sk = "abffdc040fd4c5d3eb6ce962a968f57995edfb33c78a11a466446a649f3ed82c"
        pk = "51c20cf4a8ed0e13cd65026625fe59d7ee8f8ef274a3d5575f8c30f9732cb3ed"
        sig = sign(sk, tx_hash)
        witness_cbor = witness(pk, sig)
        answer = "820082582051c20cf4a8ed0e13cd65026625fe59d7ee8f8ef274a3d5575f8c30f9732cb3ed584077589916b53ea6abfb4e9793770bf5fbb0bbe153046e12b91365832f2c1558aec34dcf8544b15fbdd1946b32b10b38dfa70defaeb827d98a4f959539000df502"
        self.assertEqual(witness_cbor, answer)

