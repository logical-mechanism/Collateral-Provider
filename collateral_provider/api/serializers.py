# api/serializers.py

import cbor2
from django.conf import settings
from rest_framework import serializers

from .simulate import evaluate_tx


class ProvideCollateralSerializer(serializers.Serializer):
    tx_body = serializers.CharField(
        allow_blank=False,    # Prevent empty strings
        trim_whitespace=True  # Automatically strip leading/trailing whitespaces
    )

    def validate_tx_body(self, tx_body_cbor):
        # the environment must be ok
        environment = self.context.get('environment')
        env_settings = self.context.get('env_settings')
        if environment not in ['preprod', 'mainnet']:
            raise serializers.ValidationError("wrong environment")

        # Ensure tx_body is not just whitespace after trimming
        if not tx_body_cbor:
            raise serializers.ValidationError("tx_body cannot be empty")
        # ensure that the cbor decodes correctly
        try:
            tx_bytes = bytes.fromhex(tx_body_cbor)
        except ValueError:
            raise serializers.ValidationError("invalid hex data in tx_body")

        # Enforce maximum transaction size
        max_tx_size = 16384  # in bytes
        tx_size = len(tx_bytes)
        if tx_size > max_tx_size:
            raise serializers.ValidationError(
                "Transaction size exceeds the maximum allowed size"
            )

        try:
            tx_body = cbor2.loads(tx_bytes)
        except cbor2.CBORDecodeError:
            raise serializers.ValidationError("invalid cbor data in tx_body")

        # ensure that the tx body decodes correctly
        if not isinstance(tx_body, list):
            raise serializers.ValidationError("tx_body is not a list")

        # cant be invalid script that purposes takes cbor
        try:
            boolean = tx_body[2]
        except IndexError:
            raise serializers.ValidationError("boolean does not exist")
        if not isinstance(boolean, bool):
            raise serializers.ValidationError("boolean is not a bool")
        if boolean is False:
            raise serializers.ValidationError("boolean can not be false")

        # ensure the actual body decodes correctly
        try:
            body = tx_body[0]
        except IndexError:
            raise serializers.ValidationError("body does not exist")
        if not isinstance(body, dict):
            raise serializers.ValidationError("body is not a dict")

        # check if inputs is correct form (0)
        try:
            inputs = body[0]
        except KeyError:
            raise serializers.ValidationError("inputs does not exist")
        if not isinstance(inputs, set):
            raise serializers.ValidationError("inputs is not a set")
        # check if collateral input is not in inputs
        being_spent_flag = False
        for utxo in inputs:
            if not isinstance(utxo, tuple):
                raise serializers.ValidationError("utxo is not a tuple")
            try:
                utxo[0]
            except IndexError:
                raise serializers.ValidationError("txid does not exist")
            if not isinstance(utxo[0], bytes):
                raise serializers.ValidationError("txid is not a bytes")
            try:
                utxo[1]
            except IndexError:
                raise serializers.ValidationError("txidx does not exist")
            if not isinstance(utxo[1], int):
                raise serializers.ValidationError("txidx is not a int")
            # put it in proper format
            tx_id = utxo[0].hex()
            tx_idx = int(utxo[1])
            if tx_id == env_settings['TXID'] and tx_idx == env_settings['TXIDX']:
                being_spent_flag = True
                break
        if being_spent_flag is True:
            raise serializers.ValidationError("collateral is being spent")

        # check if collateral inputs is correct form(13)
        try:
            collaterals = body[13]
        except KeyError:
            raise serializers.ValidationError("collaterals does not exist")
        if not isinstance(collaterals, set):
            raise serializers.ValidationError("collateral is not a set")
        # check if collateral input is in collateral inputs (13)
        being_used_flag = False
        for utxo in collaterals:
            if not isinstance(utxo, tuple):
                raise serializers.ValidationError("utxo is not a tuple")
            try:
                utxo[0]
            except IndexError:
                raise serializers.ValidationError("txid does not exist")
            if not isinstance(utxo[0], bytes):
                raise serializers.ValidationError("txid is not a bytes")
            try:
                utxo[1]
            except IndexError:
                raise serializers.ValidationError("txidx does not exist")
            if not isinstance(utxo[1], int):
                raise serializers.ValidationError("txidx is not a int")
            # put it in proper format
            tx_id = utxo[0].hex()
            tx_idx = int(utxo[1])
            if tx_id == env_settings['TXID'] and tx_idx == env_settings['TXIDX']:
                being_used_flag = True
                break
        if being_used_flag is False:
            raise serializers.ValidationError("collateral is not being used")

        # check if required signers is in correct form
        try:
            required_signers = body[14]
        except KeyError:
            raise serializers.ValidationError(
                "required signers does not exist")
        if not isinstance(required_signers, set):
            raise serializers.ValidationError("required signers is not a set")
        # check if pkh is in required signers
        being_signed_flag = False
        for signer in required_signers:
            if not isinstance(signer, bytes):
                raise serializers.ValidationError("signer is not a bytes")
            if signer.hex() == settings.PKH:
                being_signed_flag = True
                break
        if being_signed_flag is False:
            raise serializers.ValidationError(
                "public key hash is not being used")

        # Do a tx validation here
        is_valid = evaluate_tx(tx_body_cbor, environment,
                               env_settings['PROJECT_ID'])
        try:
            is_valid['result']['EvaluationResult']
        except KeyError:
            raise serializers.ValidationError("transaction fails validation")
        # at this point collateral is not being spent, its in the collateral inputs,
        # and the pkh is being used to sign the tx
        #
        # should be good
        #
        return tx_body_cbor
