import cbor2

from api.ban_list import banned_addresses
from api.util import log_and_raise_error


class CborValidator:
    def __init__(self, logger):
        self.logger = logger

    def check_cbor_hex(self, tx_body_cbor, max_tx_size=16384):
        # Ensure tx_body is not just whitespace after trimming
        if not tx_body_cbor:
            log_and_raise_error(self.logger, "tx_body cannot be empty")

        # ensure that the cbor decodes correctly
        try:
            tx_bytes = bytes.fromhex(tx_body_cbor)
        except ValueError:
            log_and_raise_error(self.logger, "invalid hex data in tx_body")

        # Enforce maximum transaction size
        tx_size = len(tx_bytes)
        if tx_size > max_tx_size:
            log_and_raise_error(self.logger, "tx_body is too large")

        # need to return the tx in byte form
        return tx_bytes

    def check_tx_body(self, tx_bytes):
        try:
            tx_body = cbor2.loads(tx_bytes)
        except cbor2.CBORDecodeError:
            log_and_raise_error(self.logger, "invalid cbor data in tx_body")

        # ensure that the tx body decodes correctly
        if not isinstance(tx_body, list):
            log_and_raise_error(self.logger, "tx_body is not a list")

        # cant be invalid script that purposes takes cbor
        try:
            boolean = tx_body[2]
        except IndexError:
            log_and_raise_error(self.logger, "boolean does not exist")
        if not isinstance(boolean, bool):
            log_and_raise_error(self.logger, "boolean is not a bool")
        if boolean is False:
            log_and_raise_error(self.logger, "boolean can not be false")

        # ensure the actual body decodes correctly
        try:
            body = tx_body[0]
        except IndexError:
            log_and_raise_error(self.logger, "body does not exist")
        if not isinstance(body, dict):
            log_and_raise_error(self.logger, "body is not a dict")

        # return the body
        return body

    def check_inputs(self, body, env_settings):
        # check if inputs is correct form (0)
        try:
            inputs = body[0]
        except KeyError:
            log_and_raise_error(self.logger, "inputs does not exist")
        if not isinstance(inputs, set):
            log_and_raise_error(self.logger, "inputs are not a set")

        # check if collateral input is not in inputs
        being_spent_flag = False
        for utxo in inputs:
            if not isinstance(utxo, tuple):
                log_and_raise_error(self.logger, "utxo is not a tuple")

            try:
                utxo[0]
            except IndexError:
                log_and_raise_error(self.logger, "txid does not exist")
            if not isinstance(utxo[0], bytes):
                log_and_raise_error(self.logger, "txid is not a bytes")

            try:
                utxo[1]
            except IndexError:
                log_and_raise_error(self.logger, "txidx does not exist")
            if not isinstance(utxo[1], int):
                log_and_raise_error(self.logger, "txidx is not a int")

            # put it in proper format
            tx_id = utxo[0].hex()
            tx_idx = int(utxo[1])
            if tx_id == env_settings['TXID'] and tx_idx == env_settings['TXIDX']:
                being_spent_flag = True
                break
        if being_spent_flag is True:
            log_and_raise_error(self.logger, "collateral is being spent")

    def check_outputs(self, body):
        try:
            outputs = body[1]
        except KeyError:
            log_and_raise_error(self.logger, "outputs do not exist in tx_body")

        if not isinstance(outputs, list):
            log_and_raise_error(self.logger, "outputs are not a list")

        for utxo in outputs:
            if not isinstance(utxo, list) and not isinstance(utxo, dict):
                log_and_raise_error(self.logger, "utxo is not a list or dict")
            try:
                utxo[0]
            except (IndexError, KeyError):
                log_and_raise_error(self.logger, "txid does not exist")

            if not isinstance(utxo[0], bytes):
                log_and_raise_error(self.logger, "txid is not a bytes")

            address = utxo[0].hex()
            if address in banned_addresses:
                log_and_raise_error(self.logger, f"{address} is banned")

    def check_collateral(self, body, env_settings):
        # check if collateral inputs is correct form(13)
        try:
            collaterals = body[13]
        except KeyError:
            log_and_raise_error(self.logger, "collaterals does not exist")

        if not isinstance(collaterals, set):
            log_and_raise_error(self.logger, "collateral is not a set")

        # check if collateral input is in collateral inputs (13)
        being_used_flag = False
        for utxo in collaterals:
            if not isinstance(utxo, tuple):
                log_and_raise_error(self.logger, "utxo is not a tuple")

            try:
                utxo[0]
            except IndexError:
                log_and_raise_error(self.logger, "txid does not exist")

            if not isinstance(utxo[0], bytes):
                log_and_raise_error(self.logger, "txid is not a bytes")

            try:
                utxo[1]
            except IndexError:
                log_and_raise_error(self.logger, "txidx does not exist")

            if not isinstance(utxo[1], int):
                log_and_raise_error(self.logger, "txidx is not a int")

            # put it in proper format
            tx_id = utxo[0].hex()
            tx_idx = int(utxo[1])
            if tx_id == env_settings['TXID'] and tx_idx == env_settings['TXIDX']:
                being_used_flag = True
                break
        if being_used_flag is False:
            log_and_raise_error(self.logger, "collateral is not being used")

    def check_signers(self, body, pkh):
        # check if required signers is in correct form
        try:
            required_signers = body[14]
        except KeyError:
            log_and_raise_error(self.logger, "required signers does not exist")

        if not isinstance(required_signers, set):
            log_and_raise_error(self.logger, "required signers is not a set")

        # check if pkh is in required signers
        being_signed_flag = False
        for signer in required_signers:
            if not isinstance(signer, bytes):
                log_and_raise_error(self.logger, "signer is not a bytes")

            if signer.hex() == pkh:
                being_signed_flag = True
                break

        if being_signed_flag is False:
            log_and_raise_error(self.logger, "public key hash is not being used")
