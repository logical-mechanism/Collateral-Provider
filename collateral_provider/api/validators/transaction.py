import logging

from rest_framework.exceptions import APIException

from api.simulate import UpstreamUnavailable, evaluate_transaction
from api.util import raise_validation_error

logger = logging.getLogger("api")


class UpstreamServiceUnavailable(APIException):
    status_code = 503
    default_detail = "Validation Service Unavailable"
    default_code = "upstream_unavailable"


def check_valid_tx(
    tx_body_cbor: str,
    environment: str,
    additional_utxos: list | None = None,
) -> None:
    """Ask Koios to evaluate the transaction. A response with a 'result' key
    means the tx is structurally and economically valid; anything else means
    it would be rejected by the chain. Network/upstream failures surface as
    503 instead of being misreported as a bad-tx 400.

    ``additional_utxos`` is forwarded as Ogmios's ``additionalUtxo`` —
    optional extra ``[txin, txout]`` pairs spliced into the chain state for
    script evaluation. Pass-through; not inspected here."""
    try:
        response = evaluate_transaction(
            tx_body_cbor, environment, additional_utxos=additional_utxos
        )
    except UpstreamUnavailable as exc:
        logger.error(f"Upstream Evaluation Unavailable: {exc}")
        raise UpstreamServiceUnavailable() from exc
    if "result" not in response:
        raise_validation_error("Transaction Fails Validation")
