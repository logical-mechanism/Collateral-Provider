from api.simulate import evaluate_transaction
from api.util import log_and_raise_error


class TransactionValidator:
    def __init__(self, logger):
        self.logger = logger

    def check_valid_tx(self, tx_body_cbor, environment):
        is_valid = evaluate_transaction(tx_body_cbor, environment)
        try:
            is_valid['result']
        except KeyError:
            log_and_raise_error(self.logger, "Transaction Fails Validation")
