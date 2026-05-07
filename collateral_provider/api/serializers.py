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
    """The request body has one field, ``tx``, holding the full transaction
    CBOR (body + witness set + is_valid + auxiliary data) hex-encoded.

    For one transition release we also accept the historical name
    ``tx_body`` as an alias — that name was misleading because the value
    is the *whole transaction*, not just the body, but renaming would
    have broken every client overnight. The alias path logs at INFO so
    operators can see who's still on the old shape, and emits the
    response under the new name regardless.
    """

    tx = serializers.CharField(allow_blank=False, trim_whitespace=True)

    LEGACY_FIELD = "tx_body"

    def to_internal_value(self, data):
        # Accept tx_body as a deprecated alias for tx. Reject the
        # ambiguous case where the client sends both — they presumably
        # meant something specific by sending the legacy name and we'd
        # rather refuse than silently pick one.
        if isinstance(data, dict):
            has_tx = "tx" in data
            has_legacy = self.LEGACY_FIELD in data
            if has_tx and has_legacy:
                raise serializers.ValidationError({
                    "tx": (
                        "Send either 'tx' or the deprecated 'tx_body', not both."
                    ),
                })
            if has_legacy and not has_tx:
                logger.info(
                    "Client used deprecated '%s' field; treating as alias for 'tx'.",
                    self.LEGACY_FIELD,
                )
                data = {**data, "tx": data[self.LEGACY_FIELD]}
        return super().to_internal_value(data)

    def validate_tx(self, tx_cbor: str) -> str:
        """Run validation in cheap-to-expensive order. The first failure
        raises ValidationError and short-circuits the rest."""
        environment = self.context["environment"]
        env_settings = self.context["env_settings"]
        ip_address = self.context["ip_address"]
        networks = self.context["networks"]

        logger.debug("Validating tx from %s", ip_address)

        check_ip_address(ip_address)
        check_environment(environment, networks)

        tx_bytes = check_cbor_hex(tx_cbor)
        body = check_tx_body(tx_bytes)
        check_inputs(body, env_settings)
        check_outputs(body)
        check_collateral(body, env_settings)
        check_signers(body, settings.PKH)

        # Most expensive check last: it's a remote HTTP call.
        check_valid_tx(tx_cbor, environment)

        return tx_cbor
