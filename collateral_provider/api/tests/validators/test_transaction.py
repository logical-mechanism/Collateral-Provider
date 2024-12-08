import unittest
from unittest.mock import Mock

from rest_framework.exceptions import ValidationError

from api.validators.transaction import TransactionValidator


class TestTransactionValidator(unittest.TestCase):

    def setUp(self):
        # Create a mock logger
        self.mock_logger = Mock()
        # Initialize TransactionValidator with the mock logger
        self.validator = TransactionValidator(self.mock_logger)

    def test_check_for_valid_tx(self):
        cbor_hex = "84A900D9010282825820E0F9A1641BE97ADD010356E8F8AC278372E2ACAC24EE21F169F861CDDB3C55C500825820E0F9A1641BE97ADD010356E8F8AC278372E2ACAC24EE21F169F861CDDB3C55C5010182A300581D7025891024CD6915AB6F7D85D43869C7BFC7021B7008BAD86E70A7C6CE011A001605BC028201D81843D87980A300581D70C757598C8D204251F0E102B5092ADF5627AEED553911CD6F82BD315401821A00184476A1581C20D133FB8814F3F6E9AA7777D73AAB7C8CDFA7D9B2D1C94BA0F94100A1582000AEB168C1C5A787D5DE5CBC0760D078BCC51B22BA8FA69E432A89137F17D9F601028201D818585BD8799F1B00000192EA62DA801B00000192EA676E601A000493E0581C20D133FB8814F3F6E9AA7777D73AAB7C8CDFA7D9B2D1C94BA0F94100582000AEB168C1C5A787D5DE5CBC0760D078BCC51B22BA8FA69E432A89137F17D9F6FF021A000186A0031A047EB7FF081A047EB5A60B582001CA3D633CA222424E36C1BA5A9CD5501FD4B19F3F6B136AF820DD4B3CCDF3490DD90102818258201D388E615DA2DCA607E28F704130D04E39DA6F251D551D66D054B75607E0393F000EA012D9010282825820680D6B17AEAC96BD3C965F6E9A6B45082870E267EA260E4AEAC31550719D315901825820724B724EC5C489DFF4D70A2CF94389AAC21F88193891A2D6B3E02B4E2997D39501A105A282000082D87A8082000082000182D87980820000F5F6"
        with self.assertRaises(ValidationError) as context:
            self.validator.check_valid_tx(cbor_hex, "preprod")

        self.assertIn("transaction fails validation", str(context.exception.detail))

    def test_check_for_invalid_tx(self):
        cbor_hex = "84a900d9010282825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c500825820e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5010dd901028182582068333201e493dd41b848bd742151c31060a749a49bc48d0b09541bcc840ac0c90012d9010282825820680d6b17aeac96bd3c965f6e9a6b45082870e267ea260e4aeac31550719d315901825820724b724ec5c489dff4d70a2cf94389aac21f88193891a2d6b3e02b4e2997d395010182a300581d7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce011a001605bc028201d81843d87980a300581d70c757598c8d204251f0e102b5092adf5627aeed553911cd6f82bd315401821a00184476a1581c20d133fb8814f3f6e9aa7777d73aab7c8cdfa7d9b2d1c94ba0f94100a1582000aeb168c1c5a787d5de5cbc0760d078bcc51b22ba8fa69e432a89137f17d9f601028201d818585fd8799f1b7fffffffffffffff1b7fffffffffffffff1b7fffffffffffffff581ca435bfe31749c3f648a16cafbcb076e6b89a1cd6928586bb5615e569582000eda6317435c61e15386c3850031a8642d24c583fad57a2ee711597af36c22aff021a000186a0031a047ef003081a047eedaa0ed9010281581cc59da4ec6e515c2efc8866274dee6ac9a64b5945efd365f3a999e7600b582001ca3d633ca222424e36c1ba5a9cd5501fd4b19f3f6b136af820dd4b3ccdf349a105a282000082d87a8082000082000182d87980820000f5f6"
        with self.assertRaises(ValidationError) as context:
            self.validator.check_valid_tx(cbor_hex, "preprod")

        self.assertIn("transaction fails validation", str(context.exception.detail))