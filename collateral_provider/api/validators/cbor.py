import cbor2

from api.ban_list import banned_addresses
from api.util import log_and_raise_error


class CborValidator:
    def __init__(self, logger):
        self.logger = logger

    def check_cbor_hex(self, tx_body_cbor, max_tx_size=16384):
        # Ensure tx_body is not just whitespace after trimming
        if not tx_body_cbor:
            log_and_raise_error(self.logger, "Tx Can't Be Empty")

        # ensure that the cbor decodes correctly
        try:
            tx_bytes = bytes.fromhex(tx_body_cbor)
        except ValueError:
            log_and_raise_error(self.logger, "Invalid Hex Data In Tx")

        # Enforce maximum transaction size
        tx_size = len(tx_bytes)
        if tx_size > max_tx_size:
            log_and_raise_error(self.logger, "Tx Is Too Large")

        # need to return the tx in byte form
        return tx_bytes

    def check_tx_body(self, tx_bytes):
        try:
            tx_body = cbor2.loads(tx_bytes)
        except cbor2.CBORDecodeError:
            log_and_raise_error(self.logger, "Invalid CBOR Data In Tx")

        # ensure that the tx body decodes correctly
        if not isinstance(tx_body, list):
            log_and_raise_error(self.logger, "Tx Is Not A List")

        # can't be invalid script that purposes takes collateral
        try:
            boolean = tx_body[2]
        except IndexError:
            log_and_raise_error(self.logger, "Boolean Does Not Exist In Tx")
        if not isinstance(boolean, bool):
            log_and_raise_error(self.logger, "Boolean Is Not A Bool")
        if boolean is False:
            log_and_raise_error(self.logger, "Boolean Can't Be False")

        # ensure the actual body decodes correctly
        try:
            body = tx_body[0]
        except IndexError:
            log_and_raise_error(self.logger, "Body Does Not Exist In Tx")
        if not isinstance(body, dict):
            log_and_raise_error(self.logger, "Tx Body Is Not A Dict")

        # return the body
        return body

    def check_inputs(self, body, env_settings):
        # check if inputs is correct form (0)
        try:
            inputs = body[0]
        except KeyError:
            log_and_raise_error(self.logger, "Inputs Does Not Exist In Body")
        if not isinstance(inputs, set):
            log_and_raise_error(self.logger, "Inputs Are Not A Set")

        # check if collateral input is not in inputs
        being_spent_flag = False
        for utxo in inputs:
            if not isinstance(utxo, tuple):
                log_and_raise_error(self.logger, "UTxO Is Not A Tuple")

            try:
                utxo[0]
            except IndexError:
                log_and_raise_error(self.logger, "TxId Does Not Exist In UTxO")
            if not isinstance(utxo[0], bytes):
                log_and_raise_error(self.logger, "TxId Is Not Bytes")

            try:
                utxo[1]
            except IndexError:
                log_and_raise_error(self.logger, "TxIdx Does Not Exist In UTxO")
            if not isinstance(utxo[1], int):
                log_and_raise_error(self.logger, "TxIdx Is Not An Int")

            # put it in proper format
            tx_id = utxo[0].hex()
            tx_idx = int(utxo[1])
            if tx_id == env_settings['TXID'] and tx_idx == env_settings['TXIDX']:
                # the tx is trying to spend the collateral
                being_spent_flag = True
                break
        if being_spent_flag is True:
            log_and_raise_error(self.logger, "Collateral Is Being Spent In Tx")

    def check_outputs(self, body):
        try:
            outputs = body[1]
        except KeyError:
            log_and_raise_error(self.logger, "Outputs Does Not Exist In Body")

        if not isinstance(outputs, list):
            log_and_raise_error(self.logger, "Outputs Are Not A List")

        for utxo in outputs:
            # has to be either shelley or babbage output
            if not isinstance(utxo, list) and not isinstance(utxo, dict):
                log_and_raise_error(self.logger, "UTxO Is Not A List Or Dict")
            try:
                utxo[0]
            except (IndexError, KeyError):
                log_and_raise_error(self.logger, "TxId Does Not Exist In UTxO")

            if not isinstance(utxo[0], bytes):
                log_and_raise_error(self.logger, "TxId Is Not Bytes")

            address = utxo[0].hex()
            if address in banned_addresses:
                log_and_raise_error(self.logger, f"The Address: {address} Is Banned")

    def check_collateral(self, body, env_settings):
        # check if collateral inputs is correct form(13)
        try:
            collaterals = body[13]
        except KeyError:
            log_and_raise_error(self.logger, "Collateral Does Not Exist In Body")

        if not isinstance(collaterals, set):
            log_and_raise_error(self.logger, "Collateral Is Not A Set")

        being_used_flag = False
        for utxo in collaterals:
            if not isinstance(utxo, tuple):
                log_and_raise_error(self.logger, "UTxO Is Not A Tuple")

            try:
                utxo[0]
            except IndexError:
                log_and_raise_error(self.logger, "TxId Does Not Exist In UTxo")

            if not isinstance(utxo[0], bytes):
                log_and_raise_error(self.logger, "TxId Is Not Bytes")

            try:
                utxo[1]
            except IndexError:
                log_and_raise_error(self.logger, "TxIdx Does Not Exist In UTxo")

            if not isinstance(utxo[1], int):
                log_and_raise_error(self.logger, "TxIdx Is Not A Int")

            # put it in proper format
            tx_id = utxo[0].hex()
            tx_idx = int(utxo[1])
            if tx_id == env_settings['TXID'] and tx_idx == env_settings['TXIDX']:
                # being used properly
                being_used_flag = True
                break
        if being_used_flag is False:
            log_and_raise_error(self.logger, "Collateral Is Not Being Used In Tx")

    def check_signers(self, body, pkh):
        # check if required signers is in correct form
        try:
            required_signers = body[14]
        except KeyError:
            log_and_raise_error(self.logger, "Required Signers Does Not Exist In Body")

        if not isinstance(required_signers, set):
            log_and_raise_error(self.logger, "Required Signers Is Not A Set")

        # check if pkh is in required signers
        being_signed_flag = False
        for signer in required_signers:
            if not isinstance(signer, bytes):
                log_and_raise_error(self.logger, "Tx Signer Is Not Bytes")

            if signer.hex() == pkh:
                being_signed_flag = True
                break

        if being_signed_flag is False:
            log_and_raise_error(self.logger, "Collateral Public Key Hash Is Not Being Used")
