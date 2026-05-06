from rest_framework.exceptions import APIException

from api.simulate import UpstreamUnavailable, evaluate_transaction
from api.util import log_and_raise_error


class UpstreamServiceUnavailable(APIException):
    status_code = 503
    default_detail = "Validation Service Unavailable"
    default_code = "upstream_unavailable"


class TransactionValidator:
    def __init__(self, logger):
        self.logger = logger

    def check_valid_tx(self, tx_body_cbor, environment):
        try:
            response = evaluate_transaction(tx_body_cbor, environment)
        except UpstreamUnavailable as exc:
            self.logger.error(f"Upstream Evaluation Unavailable: {exc}")
            raise UpstreamServiceUnavailable() from exc
        if "result" not in response:
            log_and_raise_error(self.logger, "Transaction Fails Validation")
