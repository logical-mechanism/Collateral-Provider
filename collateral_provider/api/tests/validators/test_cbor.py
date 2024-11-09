import unittest
from unittest.mock import Mock, patch

from rest_framework.exceptions import ValidationError

from api.tests.test_big_data import invalid_tx_body_too_big
from api.validators.cbor import CborValidator


class TestCborValidator(unittest.TestCase):

    def setUp(self):
        # Create a mock logger
        self.mock_logger = Mock()
        # Initialize CborValidator with the mock logger
        self.validator = CborValidator(self.mock_logger)

    def test_empty_cbor_hex(self):
        # Test for an allowed IP
        cbor_hex = ""
        with self.assertRaises(ValidationError) as context:
            self.validator.check_cbor_hex(cbor_hex)
            # Extract the error message from the ValidationError
            self.assertIn("tx_body cannot be empty", str(context.exception.detail))

    def test_not_cbor_hex(self):
        # Test for an allowed IP
        cbor_hex = "hello world"
        with self.assertRaises(ValidationError) as context:
            self.validator.check_cbor_hex(cbor_hex)
            # Extract the error message from the ValidationError
            self.assertIn("invalid hex data in tx_body", str(context.exception.detail))

    def test_too_large_cbor_hex(self):
        # Test for an allowed IP
        with self.assertRaises(ValidationError) as context:
            self.validator.check_cbor_hex(invalid_tx_body_too_big())
            # Extract the error message from the ValidationError
            self.assertIn("tx_body is too large", str(context.exception.detail))

    def test_not_valid_cbor(self):
        # Test for an allowed IP
        cbor_hex = "acab"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_tx_body(tx_bytes)
            # Extract the error message from the ValidationError
            self.assertIn("invalid cbor data in tx_body", str(context.exception.detail))

    def test_tx_body_not_list(self):
        cbor_hex = "a900d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5010dd90102818258201d388e615da2dca607e28f704130d04e39da6f251d551d66d054b75607e0393f0012d9010282825820680d6b17aeac96bd3c965f6e9a6b45082870e267ea260e4aeac31550719d315901825820724b724ec5c489dff4d70a2cf94389aac21f88193891a2d6b3e02b4e2997d395010182a300581d7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce011a001605bc028201d81843d87980a300581d70c757598c8d204251f0e102b5092adf5627aeed553911cd6f82bd315401821a00184476a1581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100a1582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f601028201d818585bd8799f1b00000192ea62da801b00000192ea676e601a000493e0581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f6ff021a000186a0031a047eb7ff081a047eb5a60ed9010281581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f40b582001ca3d633ca222424e36c1ba5a9cd5501fd4b19f3f6b136af820dd4b3ccdf349a105a282000082d87a8082000082000182d87980820000"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_tx_body(tx_bytes)
            # Extract the error message from the ValidationError
            self.assertIn("tx_body is not a list", str(context.exception.detail))

    def test_missing_boolean(self):
        cbor_hex = "82a900d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5010dd90102818258201d388e615da2dca607e28f704130d04e39da6f251d551d66d054b75607e0393f0012d9010282825820680d6b17aeac96bd3c965f6e9a6b45082870e267ea260e4aeac31550719d315901825820724b724ec5c489dff4d70a2cf94389aac21f88193891a2d6b3e02b4e2997d395010182a300581d7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce011a001605bc028201d81843d87980a300581d70c757598c8d204251f0e102b5092adf5627aeed553911cd6f82bd315401821a00184476a1581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100a1582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f601028201d818585bd8799f1b00000192ea62da801b00000192ea676e601a000493e0581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f6ff021a000186a0031a047eb7ff081a047eb5a60ed9010281581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f40b582001ca3d633ca222424e36c1ba5a9cd5501fd4b19f3f6b136af820dd4b3ccdf349a105a282000082d87a8082000082000182d87980820000"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_tx_body(tx_bytes)
            # Extract the error message from the ValidationError
            self.assertIn("boolean does not exist", str(context.exception.detail))

    def test_not_a_bool(self):
        cbor_hex = "84a900d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5010dd90102818258201d388e615da2dca607e28f704130d04e39da6f251d551d66d054b75607e0393f0012d9010282825820680d6b17aeac96bd3c965f6e9a6b45082870e267ea260e4aeac31550719d315901825820724b724ec5c489dff4d70a2cf94389aac21f88193891a2d6b3e02b4e2997d395010182a300581d7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce011a001605bc028201d81843d87980a300581d70c757598c8d204251f0e102b5092adf5627aeed553911cd6f82bd315401821a00184476a1581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100a1582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f601028201d818585bd8799f1b00000192ea62da801b00000192ea676e601a000493e0581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f6ff021a000186a0031a047eb7ff081a047eb5a60ed9010281581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f40b582001ca3d633ca222424e36c1ba5a9cd5501fd4b19f3f6b136af820dd4b3ccdf349a105a282000082d87a8082000082000182d8798082000000f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_tx_body(tx_bytes)
            # Extract the error message from the ValidationError
            self.assertIn("boolean is not a bool", str(context.exception.detail))

    def test_bool_is_false(self):
        cbor_hex = "84a900d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5010dd90102818258201d388e615da2dca607e28f704130d04e39da6f251d551d66d054b75607e0393f0012d9010282825820680d6b17aeac96bd3c965f6e9a6b45082870e267ea260e4aeac31550719d315901825820724b724ec5c489dff4d70a2cf94389aac21f88193891a2d6b3e02b4e2997d395010182a300581d7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce011a001605bc028201d81843d87980a300581d70c757598c8d204251f0e102b5092adf5627aeed553911cd6f82bd315401821a00184476a1581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100a1582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f601028201d818585bd8799f1b00000192ea62da801b00000192ea676e601a000493e0581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f6ff021a000186a0031a047eb7ff081a047eb5a60ed9010281581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f40b582001ca3d633ca222424e36c1ba5a9cd5501fd4b19f3f6b136af820dd4b3ccdf349a105a282000082d87a8082000082000182d87980820000f4f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_tx_body(tx_bytes)
            # Extract the error message from the ValidationError
            self.assertIn("boolean can not be false", str(context.exception.detail))

    def test_body_is_not_dict(self):
        cbor_hex = "83825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500f5f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_tx_body(tx_bytes)
            # Extract the error message from the ValidationError
            self.assertIn("body is not a dict", str(context.exception.detail))

    def test_inputs_dont_exist(self):
        cbor_hex = "84a0a0f5f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_inputs(body, {})
            # Extract the error message from the ValidationError
            self.assertIn("inputs does not exist", str(context.exception.detail))

    def test_inputs_are_not_a_set(self):
        cbor_hex = "84a100a0a0f5f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_inputs(body, {})
            # Extract the error message from the ValidationError
            self.assertIn("inputs are not a set", str(context.exception.detail))

    def test_inputs_are_spending_collat(self):
        cbor_hex = "84a100a0a0f5f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_inputs(body, {'TXID': 'e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5', 'TXIDX': 0})
            # Extract the error message from the ValidationError
            self.assertIn("collateral is being spent", str(context.exception.detail))

    def test_outputs_dont_exist(self):
        cbor_hex = "84a100d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c501a105a282000082d87a8082000082000182d87980820000f5f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_outputs(body)
            # Extract the error message from the ValidationError
            self.assertIn("outputs do not exist in tx_body", str(context.exception.detail))

    def test_outputs_is_not_list(self):
        cbor_hex = "84a900d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c50101a0021a000186a0031a047eb7ff081a047eb5a60b582001ca3d633ca222424e36c1ba5a9cd5501fd4b19f3f6b136af820dd4b3ccdf3490dd90102818258201d388e615da2dca607e28f704130d04e39da6f251d551d66d054b75607e0393f000ed9010281581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f412d9010282825820680d6b17aeac96bd3c965f6e9a6b45082870e267ea260e4aeac31550719d315901825820724b724ec5c489dff4d70a2cf94389aac21f88193891a2d6b3e02b4e2997d39501a105a282000082d87a8082000082000182d87980820000f5f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_outputs(body)
            # Extract the error message from the ValidationError
            self.assertIn("outputs are not a list", str(context.exception.detail))

    @patch("api.validators.cbor.banned_addresses", ["7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce"])
    def test_check_address_banned(self):
        address = "7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce"
        cbor_hex = "84a900d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5010182a300581d7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce011a001605bc028201d81843d87980a300581d70c757598c8d204251f0e102b5092adf5627aeed553911cd6f82bd315401821a00184476a1581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100a1582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f601028201d818585bd8799f1b00000192ea62da801b00000192ea676e601a000493e0581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f6ff021a000186a0031a047eb7ff081a047eb5a60b582001ca3d633ca222424e36c1ba5a9cd5501fd4b19f3f6b136af820dd4b3ccdf3490dd90102818258201d388e615da2dca607e28f704130d04e39da6f251d551d66d054b75607e0393f000ed9010281581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f412d9010282825820680d6b17aeac96bd3c965f6e9a6b45082870e267ea260e4aeac31550719d315901825820724b724ec5c489dff4d70a2cf94389aac21f88193891a2d6b3e02b4e2997d39501a105a282000082d87a8082000082000182d87980820000f5f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_outputs(body)

        # Extract the error message from the ValidationError
        self.assertIn(f"{address} is banned", str(context.exception.detail))

    def test_collateral_does_not_exist(self):
        cbor_hex = "84a800d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5010182a300581d7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce011a001605bc028201d81843d87980a300581d70c757598c8d204251f0e102b5092adf5627aeed553911cd6f82bd315401821a00184476a1581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100a1582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f601028201d818585bd8799f1b00000192ea62da801b00000192ea676e601a000493e0581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f6ff021a000186a0031a047eb7ff081a047eb5a60b582001ca3d633ca222424e36c1ba5a9cd5501fd4b19f3f6b136af820dd4b3ccdf3490ed9010281581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f412d9010282825820680d6b17aeac96bd3c965f6e9a6b45082870e267ea260e4aeac31550719d315901825820724b724ec5c489dff4d70a2cf94389aac21f88193891a2d6b3e02b4e2997d39501a105a282000082d87a8082000082000182d87980820000f5f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_collateral(body, {})

        # Extract the error message from the ValidationError
        self.assertIn("collaterals does not exist", str(context.exception.detail))

    def test_collateral_is_not_set(self):
        cbor_hex = "84a900d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5010182a300581d7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce011a001605bc028201d81843d87980a300581d70c757598c8d204251f0e102b5092adf5627aeed553911cd6f82bd315401821a00184476a1581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100a1582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f601028201d818585bd8799f1b00000192ea62da801b00000192ea676e601a000493e0581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f6ff021a000186a0031a047eb7ff081a047eb5a60b582001ca3d633ca222424e36c1ba5a9cd5501fd4b19f3f6b136af820dd4b3ccdf3490da00ed9010281581c7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f412d9010282825820680d6b17aeac96bd3c965f6e9a6b45082870e267ea260e4aeac31550719d315901825820724b724ec5c489dff4d70a2cf94389aac21f88193891a2d6b3e02b4e2997d39501a105a282000082d87a8082000082000182d87980820000f5f6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_collateral(body, {})

        # Extract the error message from the ValidationError
        self.assertIn("collateral is not a set", str(context.exception.detail))

    def test_collateral_not_being_used(self):
        cbor_hex = "84A900D9010282825820E0F9A1641BE97ADD010356E8F8AC278372E2ACAC24EE21F169F861CDDB3C55C500825820E0F9A1641BE97ADD010356E8F8AC278372E2ACAC24EE21F169F861CDDB3C55C5010182A300581D7025891024CD6915AB6F7D85D43869C7BFC7021B7008BAD86E70A7C6CE011A001605BC028201D81843D87980A300581D70C757598C8D204251F0E102B5092ADF5627AEED553911CD6F82BD315401821A00184476A1581C20D133FB8814F3F6E9AA7777D73AAB7C8CDFA7D9B2D1C94BA0F94100A1582000AEB168C1C5A787D5DE5CBC0760D078BCC51B22BA8FA69E432A89137F17D9F601028201D818585BD8799F1B00000192EA62DA801B00000192EA676E601A000493E0581C20D133FB8814F3F6E9AA7777D73AAB7C8CDFA7D9B2D1C94BA0F94100582000AEB168C1C5A787D5DE5CBC0760D078BCC51B22BA8FA69E432A89137F17D9F6FF021A000186A0031A047EB7FF081A047EB5A60B582001CA3D633CA222424E36C1BA5A9CD5501FD4B19F3F6B136AF820DD4B3CCDF3490DD90102818258201D388E615DA2DCA607E28F704130D04E39DA6F251D551D66D054B75607E0393F000ED9010281581C7C24C22D1DC252D31F6022FF22CCC838C2AB83A461172D7C2DAE61F412D9010282825820680D6B17AEAC96BD3C965F6E9A6B45082870E267EA260E4AEAC31550719D315901825820724B724EC5C489DFF4D70A2CF94389AAC21F88193891A2D6B3E02B4E2997D39501A105A282000082D87A8082000082000182D87980820000F5F6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_collateral(body, {'TXID': 'e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5', 'TXIDX': 0})

        # Extract the error message from the ValidationError
        self.assertIn("collateral is not being used", str(context.exception.detail))

    def test_signer_does_not_exist(self):
        cbor_hex = "84A800D9010282825820E0F9A1641BE97ADD010356E8F8AC278372E2ACAC24EE21F169F861CDDB3C55C500825820E0F9A1641BE97ADD010356E8F8AC278372E2ACAC24EE21F169F861CDDB3C55C5010182A300581D7025891024CD6915AB6F7D85D43869C7BFC7021B7008BAD86E70A7C6CE011A001605BC028201D81843D87980A300581D70C757598C8D204251F0E102B5092ADF5627AEED553911CD6F82BD315401821A00184476A1581C20D133FB8814F3F6E9AA7777D73AAB7C8CDFA7D9B2D1C94BA0F94100A1582000AEB168C1C5A787D5DE5CBC0760D078BCC51B22BA8FA69E432A89137F17D9F601028201D818585BD8799F1B00000192EA62DA801B00000192EA676E601A000493E0581C20D133FB8814F3F6E9AA7777D73AAB7C8CDFA7D9B2D1C94BA0F94100582000AEB168C1C5A787D5DE5CBC0760D078BCC51B22BA8FA69E432A89137F17D9F6FF021A000186A0031A047EB7FF081A047EB5A60B582001CA3D633CA222424E36C1BA5A9CD5501FD4B19F3F6B136AF820DD4B3CCDF3490DD90102818258201D388E615DA2DCA607E28F704130D04E39DA6F251D551D66D054B75607E0393F0012D9010282825820680D6B17AEAC96BD3C965F6E9A6B45082870E267EA260E4AEAC31550719D315901825820724B724EC5C489DFF4D70A2CF94389AAC21F88193891A2D6B3E02B4E2997D39501A105A282000082D87A8082000082000182D87980820000F5F6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_signers(body, '')

        # Extract the error message from the ValidationError
        self.assertIn("required signers does not exist", str(context.exception.detail))

    def test_signer_is_not_set(self):
        cbor_hex = "84A900D9010282825820E0F9A1641BE97ADD010356E8F8AC278372E2ACAC24EE21F169F861CDDB3C55C500825820E0F9A1641BE97ADD010356E8F8AC278372E2ACAC24EE21F169F861CDDB3C55C5010182A300581D7025891024CD6915AB6F7D85D43869C7BFC7021B7008BAD86E70A7C6CE011A001605BC028201D81843D87980A300581D70C757598C8D204251F0E102B5092ADF5627AEED553911CD6F82BD315401821A00184476A1581C20D133FB8814F3F6E9AA7777D73AAB7C8CDFA7D9B2D1C94BA0F94100A1582000AEB168C1C5A787D5DE5CBC0760D078BCC51B22BA8FA69E432A89137F17D9F601028201D818585BD8799F1B00000192EA62DA801B00000192EA676E601A000493E0581C20D133FB8814F3F6E9AA7777D73AAB7C8CDFA7D9B2D1C94BA0F94100582000AEB168C1C5A787D5DE5CBC0760D078BCC51B22BA8FA69E432A89137F17D9F6FF021A000186A0031A047EB7FF081A047EB5A60B582001CA3D633CA222424E36C1BA5A9CD5501FD4B19F3F6B136AF820DD4B3CCDF3490DD90102818258201D388E615DA2DCA607E28F704130D04E39DA6F251D551D66D054B75607E0393F000EA012D9010282825820680D6B17AEAC96BD3C965F6E9A6B45082870E267EA260E4AEAC31550719D315901825820724B724EC5C489DFF4D70A2CF94389AAC21F88193891A2D6B3E02B4E2997D39501A105A282000082D87A8082000082000182D87980820000F5F6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_signers(body, '')

        # Extract the error message from the ValidationError
        self.assertIn("required signers is not a set", str(context.exception.detail))

    def test_signer_is_not_used(self):
        cbor_hex = "84A900D9010282825820E0F9A1641BE97ADD010356E8F8AC278372E2ACAC24EE21F169F861CDDB3C55C500825820E0F9A1641BE97ADD010356E8F8AC278372E2ACAC24EE21F169F861CDDB3C55C5010182A300581D7025891024CD6915AB6F7D85D43869C7BFC7021B7008BAD86E70A7C6CE011A001605BC028201D81843D87980A300581D70C757598C8D204251F0E102B5092ADF5627AEED553911CD6F82BD315401821A00184476A1581C20D133FB8814F3F6E9AA7777D73AAB7C8CDFA7D9B2D1C94BA0F94100A1582000AEB168C1C5A787D5DE5CBC0760D078BCC51B22BA8FA69E432A89137F17D9F601028201D818585BD8799F1B00000192EA62DA801B00000192EA676E601A000493E0581C20D133FB8814F3F6E9AA7777D73AAB7C8CDFA7D9B2D1C94BA0F94100582000AEB168C1C5A787D5DE5CBC0760D078BCC51B22BA8FA69E432A89137F17D9F6FF021A000186A0031A047EB7FF081A047EB5A60B582001CA3D633CA222424E36C1BA5A9CD5501FD4B19F3F6B136AF820DD4B3CCDF3490DD90102818258201D388E615DA2DCA607E28F704130D04E39DA6F251D551D66D054B75607E0393F000ED9010281581C7C24C22D1DC252D31F6022FF22CCC838C2AB83A461172D7C2DAE61F412D9010282825820680D6B17AEAC96BD3C965F6E9A6B45082870E267EA260E4AEAC31550719D315901825820724B724EC5C489DFF4D70A2CF94389AAC21F88193891A2D6B3E02B4E2997D39501A105A282000082D87A8082000082000182D87980820000F5F6"
        tx_bytes = self.validator.check_cbor_hex(cbor_hex)
        body = self.validator.check_tx_body(tx_bytes)
        with self.assertRaises(ValidationError) as context:
            self.validator.check_signers(body, 'ac24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f4')

        # Extract the error message from the ValidationError
        self.assertIn("public key hash is not being used", str(context.exception.detail))
