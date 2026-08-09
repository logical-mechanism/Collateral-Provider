"""Request shape for the collateral endpoint.

This serializer only validates the *shape* of the JSON body. The
business pipeline (ban / env / CBOR / inputs / outputs / collateral /
signers / upstream evaluation) lives in
``api.services.collateral.issue_witness`` so the serializer stays free
of DRF↔HTTP-client coupling.
"""

from rest_framework import serializers


class ProvideCollateralSerializer(serializers.Serializer):
    """The request body has one required field, ``tx``, holding the full
    transaction CBOR (body + witness set + is_valid + auxiliary data)
    hex-encoded.

    ``additional_utxos`` is retained only as an empty-value compatibility
    field. A caller-supplied output for an unsubmitted parent transaction
    cannot be authenticated from its reference, so non-empty values must
    never reach the evaluator.
    """

    tx = serializers.CharField(allow_blank=False, trim_whitespace=True)
    additional_utxos = serializers.ListField(
        required=False,
        allow_empty=True,
        child=serializers.JSONField(),
        help_text=(
            "Reserved compatibility field. It must be omitted or empty; "
            "caller-supplied UTxOs are never forwarded to the evaluator."
        ),
    )

    def validate_additional_utxos(self, value):
        if value:
            raise serializers.ValidationError(
                "additional_utxos is not supported; submit only ledger-resolved inputs."
            )
        return None
