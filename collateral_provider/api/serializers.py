"""Request shape for the collateral endpoint.

This serializer only validates the *shape* of the JSON body. The
business pipeline (ban / env / CBOR / inputs / outputs / collateral /
signers / upstream evaluation) lives in
``api.services.collateral.issue_witness`` so the serializer stays free
of DRF↔HTTP-client coupling.
"""

import json

from rest_framework import serializers

# Cap the JSON-encoded `additional_utxos` field. A single Cardano UTxO
# can hold up to ~16 KiB on chain; 32 KiB gives generous headroom for
# a couple of large pre-chain UTxOs forwarded as Ogmios additionalUtxo.
# The wider request body cap (DATA_UPLOAD_MAX_MEMORY_SIZE) catches
# anything larger than that anyway, but pinning the field cap here
# means we reject without dragging the whole body into the validator.
ADDITIONAL_UTXOS_MAX_BYTES = 32 * 1024


class ProvideCollateralSerializer(serializers.Serializer):
    """The request body has one required field, ``tx``, holding the full
    transaction CBOR (body + witness set + is_valid + auxiliary data)
    hex-encoded. An optional ``additional_utxos`` field carries extra
    ``[txin, txout]`` pairs that get forwarded verbatim to Ogmios as
    ``additionalUtxo`` so script evaluation can see UTxOs created by
    transactions not yet on chain.
    """

    tx = serializers.CharField(allow_blank=False, trim_whitespace=True)
    # Loose by design: we don't mirror Ogmios's full UTxO schema here.
    # We do enforce the [txin, txout] pair shape and a total-bytes cap
    # in validate_additional_utxos so a malformed or oversized payload
    # fails locally instead of burning a Koios round-trip.
    additional_utxos = serializers.ListField(
        required=False,
        allow_empty=True,
        child=serializers.JSONField(),
        help_text=(
            "Optional list of [txin, txout] pairs spliced into the chain "
            "state for script evaluation. Forwarded to Ogmios as "
            "`additionalUtxo`. Missing or empty is fine — skipped."
        ),
    )

    def validate_additional_utxos(self, value):
        """Cap size, require each entry to be a 2-element list of dicts.

        Empty input is normalized to ``None`` so the service treats it
        as "skip" without a separate check.
        """
        if not value:
            return None

        for entry in value:
            if not (isinstance(entry, list) and len(entry) == 2):
                raise serializers.ValidationError(
                    "Each additional_utxos entry must be a [txin, txout] pair."
                )
            if not (isinstance(entry[0], dict) and isinstance(entry[1], dict)):
                raise serializers.ValidationError(
                    "Both elements of an additional_utxos entry must be objects."
                )

        encoded_size = len(json.dumps(value))
        if encoded_size > ADDITIONAL_UTXOS_MAX_BYTES:
            raise serializers.ValidationError(
                f"additional_utxos exceeds {ADDITIONAL_UTXOS_MAX_BYTES} bytes."
            )

        return value
