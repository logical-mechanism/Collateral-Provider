import logging

from django.conf import settings
from rest_framework import serializers

from .validators.cbor import CborValidator
from .validators.environment import EnvironmentValidator
from .validators.transaction import TransactionValidator

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
        networks = self.context.get('networks')

        logger.debug(f"Validating Tx Body From {ip_address}")

        env_validator = EnvironmentValidator(logger)
        env_validator.check_ip_address(ip_address)
        env_validator.check_environment(environment, networks)

        cbor_validator = CborValidator(logger)
        tx_bytes = cbor_validator.check_cbor_hex(tx_body_cbor)
        body = cbor_validator.check_tx_body(tx_bytes)
        cbor_validator.check_inputs(body, env_settings)
        cbor_validator.check_outputs(body)
        cbor_validator.check_collateral(body, env_settings)
        cbor_validator.check_signers(body, settings.PKH)

        tx_validator = TransactionValidator(logger)
        tx_validator.check_valid_tx(tx_body_cbor, environment)

        # At this point collateral is not being spent, it's in the collateral inputs,
        # the pkh is being used to sign the tx, and the tx is valid.
        return tx_body_cbor
