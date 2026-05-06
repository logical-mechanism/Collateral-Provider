import logging

from django.conf import settings
from rest_framework import serializers

from api.validators.cbor import (
    check_cbor_hex,
    check_collateral,
    check_inputs,
    check_outputs,
    check_signers,
    check_tx_body,
)
from api.validators.environment import check_environment, check_ip_address
from api.validators.transaction import check_valid_tx

logger = logging.getLogger("api")


class ProvideCollateralSerializer(serializers.Serializer):
    tx_body = serializers.CharField(allow_blank=False, trim_whitespace=True)

    def validate_tx_body(self, tx_body_cbor: str) -> str:
        """Run validation in cheap-to-expensive order. The first failure
        raises ValidationError and short-circuits the rest."""
        environment = self.context["environment"]
        env_settings = self.context["env_settings"]
        ip_address = self.context["ip_address"]
        networks = self.context["networks"]

        logger.debug(f"Validating Tx Body From {ip_address}")

        check_ip_address(ip_address)
        check_environment(environment, networks)

        tx_bytes = check_cbor_hex(tx_body_cbor)
        body = check_tx_body(tx_bytes)
        check_inputs(body, env_settings)
        check_outputs(body)
        check_collateral(body, env_settings)
        check_signers(body, settings.PKH)

        # Most expensive check last: it's a remote HTTP call.
        check_valid_tx(tx_body_cbor, environment)

        return tx_body_cbor
