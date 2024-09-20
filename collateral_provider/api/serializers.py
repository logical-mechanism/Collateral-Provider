# api/serializers.py

import logging

import cbor2
from django.conf import settings
from rest_framework import serializers

from .ban_list import banned_ip_address
from .simulate import evaluate_tx

# Initialize the logger
logger = logging.getLogger('api')


class ProvideCollateralSerializer(serializers.Serializer):
    tx_body = serializers.CharField(
        allow_blank=False,    # Prevent empty strings
        trim_whitespace=True  # Automatically strip leading/trailing whitespaces
    )

    def validate_tx_body(self, tx_body_cbor):
        # the environment must be ok
        environment = self.context.get('environment')
        env_settings = self.context.get('env_settings')
        ip_address = self.context.get('ip_address')

        logger.info(f"Validating tx_body for request from {ip_address}")

        if ip_address in banned_ip_address:
            logger.error(
                f"{ip_address} is banned")
            raise serializers.ValidationError("ip address is banned")

        if environment not in ['preprod', 'mainnet']:
            logger.error(
                f"Invalid environment {environment} from {ip_address}")
            raise serializers.ValidationError("wrong environment")

        # Ensure tx_body is not just whitespace after trimming
        if not tx_body_cbor:
            logger.error(f"Empty tx_body from {ip_address}")
            raise serializers.ValidationError("tx_body cannot be empty")

        # ensure that the cbor decodes correctly
        try:
            tx_bytes = bytes.fromhex(tx_body_cbor)
        except ValueError:
            logger.error(f"Invalid hex data in tx_body from {ip_address}")
            raise serializers.ValidationError("invalid hex data in tx_body")

        # Enforce maximum transaction size
        max_tx_size = 16384  # in bytes
        tx_size = len(tx_bytes)
        if tx_size > max_tx_size:
            logger.error(f"Transaction size exceeds maximum from {ip_address}")
            raise serializers.ValidationError(
                "Transaction size exceeds the maximum allowed size")

        try:
            tx_body = cbor2.loads(tx_bytes)
        except cbor2.CBORDecodeError:
            logger.error(f"Invalid CBOR data in tx_body from {ip_address}")
            raise serializers.ValidationError("invalid cbor data in tx_body")

        # ensure that the tx body decodes correctly
        if not isinstance(tx_body, list):
            logger.error(f"tx_body is not a list from {ip_address}")
            raise serializers.ValidationError("tx_body is not a list")

        # cant be invalid script that purposes takes cbor
        try:
            boolean = tx_body[2]
        except IndexError:
            logger.error(
                f"Boolean does not exist in tx_body from {ip_address}")
            raise serializers.ValidationError("boolean does not exist")
        if not isinstance(boolean, bool):
            logger.error(f"Boolean is not a bool in tx_body from {ip_address}")
            raise serializers.ValidationError("boolean is not a bool")
        if boolean is False:
            logger.error(f"Boolean is false in tx_body from {ip_address}")
            raise serializers.ValidationError("boolean can not be false")

        # ensure the actual body decodes correctly
        try:
            body = tx_body[0]
        except IndexError:
            logger.error(f"Body does not exist in tx_body from {ip_address}")
            raise serializers.ValidationError("body does not exist")
        if not isinstance(body, dict):
            logger.error(f"Body is not a dict in tx_body from {ip_address}")
            raise serializers.ValidationError("body is not a dict")

        # check if inputs is correct form (0)
        try:
            inputs = body[0]
        except KeyError:
            logger.error(f"Inputs do not exist in tx_body from {ip_address}")
            raise serializers.ValidationError("inputs does not exist")
        if not isinstance(inputs, set):
            logger.error(f"Inputs is not a set in tx_body from {ip_address}")
            raise serializers.ValidationError("inputs is not a set")

        # check if collateral input is not in inputs
        being_spent_flag = False
        for utxo in inputs:
            if not isinstance(utxo, tuple):
                logger.error(
                    f"UTXO is not a tuple in tx_body from {ip_address}")
                raise serializers.ValidationError("utxo is not a tuple")
            try:
                utxo[0]
            except IndexError:
                logger.error(
                    f"txid does not exist in tx_body from {ip_address}")
                raise serializers.ValidationError("txid does not exist")
            if not isinstance(utxo[0], bytes):
                logger.error(f"txid is not bytes in tx_body from {ip_address}")
                raise serializers.ValidationError("txid is not a bytes")
            try:
                utxo[1]
            except IndexError:
                logger.error(
                    f"txidx does not exist in tx_body from {ip_address}")
                raise serializers.ValidationError("txidx does not exist")
            if not isinstance(utxo[1], int):
                logger.error(
                    f"txidx is not an int in tx_body from {ip_address}")
                raise serializers.ValidationError("txidx is not a int")
            # put it in proper format
            tx_id = utxo[0].hex()
            tx_idx = int(utxo[1])
            if tx_id == env_settings['TXID'] and tx_idx == env_settings['TXIDX']:
                being_spent_flag = True
                break
        if being_spent_flag is True:
            logger.error(
                f"Collateral is being spent in tx_body from {ip_address}")
            raise serializers.ValidationError("collateral is being spent")

        # check if collateral inputs is correct form(13)
        try:
            collaterals = body[13]
        except KeyError:
            logger.error(
                f"Collaterals do not exist in tx_body from {ip_address}")
            raise serializers.ValidationError("collaterals does not exist")
        if not isinstance(collaterals, set):
            logger.error(
                f"Collaterals is not a set in tx_body from {ip_address}")
            raise serializers.ValidationError("collateral is not a set")

        # check if collateral input is in collateral inputs (13)
        being_used_flag = False
        for utxo in collaterals:
            if not isinstance(utxo, tuple):
                logger.error(
                    f"UTXO is not a tuple in collaterals from {ip_address}")
                raise serializers.ValidationError("utxo is not a tuple")
            try:
                utxo[0]
            except IndexError:
                logger.error(
                    f"txid does not exist in collaterals from {ip_address}")
                raise serializers.ValidationError("txid does not exist")
            if not isinstance(utxo[0], bytes):
                logger.error(
                    f"txid is not bytes in collaterals from {ip_address}")
                raise serializers.ValidationError("txid is not a bytes")
            try:
                utxo[1]
            except IndexError:
                logger.error(
                    f"txidx does not exist in collaterals from {ip_address}")
                raise serializers.ValidationError("txidx does not exist")
            if not isinstance(utxo[1], int):
                logger.error(
                    f"txidx is not an int in collaterals from {ip_address}")
                raise serializers.ValidationError("txidx is not a int")
            # put it in proper format
            tx_id = utxo[0].hex()
            tx_idx = int(utxo[1])
            if tx_id == env_settings['TXID'] and tx_idx == env_settings['TXIDX']:
                being_used_flag = True
                break
        if being_used_flag is False:
            logger.error(
                f"Collateral is not being used in tx_body from {ip_address}")
            raise serializers.ValidationError("collateral is not being used")

        # check if required signers is in correct form
        try:
            required_signers = body[14]
        except KeyError:
            logger.error(
                f"Required signers do not exist in tx_body from {ip_address}")
            raise serializers.ValidationError(
                "required signers does not exist")
        if not isinstance(required_signers, set):
            logger.error(
                f"Required signers is not a set in tx_body from {ip_address}")
            raise serializers.ValidationError("required signers is not a set")

        # check if pkh is in required signers
        being_signed_flag = False
        for signer in required_signers:
            if not isinstance(signer, bytes):
                logger.error(
                    f"Signer is not bytes in required signers from {ip_address}")
                raise serializers.ValidationError("signer is not a bytes")
            if signer.hex() == settings.PKH:
                being_signed_flag = True
                break
        if being_signed_flag is False:
            logger.error(
                f"Public key hash is not being used in tx_body from {ip_address}")
            raise serializers.ValidationError(
                "public key hash is not being used")

        # Do a tx validation here
        is_valid = evaluate_tx(tx_body_cbor, environment,
                               env_settings['PROJECT_ID'])
        try:
            is_valid['result']['EvaluationResult']
        except KeyError:
            logger.error(
                f"Transaction fails validation for request from {ip_address}")
            raise serializers.ValidationError("transaction fails validation")

        logger.info(
            f"Successfully validated tx_body for request from {ip_address}")

        # At this point collateral is not being spent, it's in the collateral inputs,
        # and the pkh is being used to sign the tx
        return tx_body_cbor
