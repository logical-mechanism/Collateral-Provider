"""Request shape for the collateral endpoint.

This serializer only validates the *shape* of the JSON body. The
business pipeline (ban / env / CBOR / inputs / outputs / collateral /
signers / upstream evaluation) lives in
``api.services.collateral.issue_witness`` so the serializer stays free
of DRF↔HTTP-client coupling.
"""

import json

from django.conf import settings
from rest_framework import serializers

# Practical cap on the count of `additional_utxos` entries. The byte cap
# (settings.ADDITIONAL_UTXOS_MAX_BYTES) catches large entries; this
# count cap catches the orthogonal case of many tiny entries that would
# pass the byte cap but still make Koios chew through hundreds of UTxOs
# per request. Real workloads need 1-5 entries; 400 is far above any
# legitimate use.
ADDITIONAL_UTXOS_MAX_COUNT = 400


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
    # Each entry may be either:
    #   * a ``[txin, txout]`` 2-element list of objects (matching the
    #     prose docs at ogmios.dev/mini-protocols/local-tx-submission),
    #     or
    #   * a flat ``Utxo`` object (matching Ogmios v6's actual JSON-RPC
    #     schema — what callers learn when they build against Koios
    #     directly).
    # ``simulate.py`` normalizes both to the flat shape Ogmios expects.
    # We still enforce a per-request count cap and a total-bytes cap so
    # a malformed or oversized payload fails locally instead of burning
    # a Koios round-trip.
    additional_utxos = serializers.ListField(
        required=False,
        allow_empty=True,
        max_length=ADDITIONAL_UTXOS_MAX_COUNT,
        child=serializers.JSONField(),
        help_text=(
            "Optional list of UTxOs spliced into the chain state for "
            "script evaluation. Each entry may be either a "
            "`[txin, txout]` pair or a flat Ogmios v6 Utxo object. "
            "Forwarded to Ogmios as `additionalUtxo`. Missing or empty "
            f"is fine — skipped. At most {ADDITIONAL_UTXOS_MAX_COUNT} entries."
        ),
    )

    def validate_additional_utxos(self, value):
        """Cap size; each entry must be either a ``[txin, txout]`` pair
        of objects or a single flat object.

        Empty input is normalized to ``None`` so the service treats it
        as "skip" without a separate check.
        """
        if not value:
            return None

        for entry in value:
            if isinstance(entry, dict):
                continue
            if isinstance(entry, list):
                if len(entry) != 2 or not (
                    isinstance(entry[0], dict) and isinstance(entry[1], dict)
                ):
                    raise serializers.ValidationError(
                        "Each [txin, txout] entry must be a 2-element list of objects."
                    )
                continue
            raise serializers.ValidationError(
                "Each additional_utxos entry must be a [txin, txout] pair "
                "or a flat Utxo object."
            )

        encoded_size = len(json.dumps(value))
        if encoded_size > settings.ADDITIONAL_UTXOS_MAX_BYTES:
            raise serializers.ValidationError(
                f"additional_utxos exceeds {settings.ADDITIONAL_UTXOS_MAX_BYTES} bytes."
            )

        return value
