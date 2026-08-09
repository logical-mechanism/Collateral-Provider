import logging
import re

import cbor2
from rest_framework.exceptions import APIException

from api.script_integrity import ScriptIntegrityError, verify_script_data_hash
from api.simulate import (
    ProtocolParametersUnavailable,
    UpstreamUnavailable,
    evaluate_transaction,
    get_protocol_cost_models,
)
from api.util import raise_validation_error

logger = logging.getLogger("api")

_REDEEMERS = 5
_UINT64_MAX = (1 << 64) - 1
_VALIDATOR_POINTER_RE = re.compile(
    r"^(spend|mint|publish|certificate|withdraw|withdrawal|vote|propose|guard):([0-9]{1,20})$"
)
_PURPOSE_TAGS = {
    "spend": 0,
    "mint": 1,
    # Ogmios has used both the ledger-facing and client-facing names for
    # certificate scripts across API generations.
    "publish": 2,
    "certificate": 2,
    "withdraw": 3,
    "withdrawal": 3,
    "vote": 4,
    "propose": 5,
    "guard": 6,
}


class UpstreamServiceUnavailable(APIException):
    status_code = 503
    default_detail = "Validation Service Unavailable"
    default_code = "upstream_unavailable"


def _is_evaluation_result(value) -> bool:
    if not isinstance(value, dict):
        return False
    validator = value.get("validator")
    budget = value.get("budget")
    if not isinstance(validator, str) or not validator:
        return False
    if not isinstance(budget, dict):
        return False
    for field in ("memory", "cpu"):
        amount = budget.get(field)
        if (
            not isinstance(amount, int)
            or isinstance(amount, bool)
            or amount < 0
            or amount > _UINT64_MAX
        ):
            return False
    return True


def _uint(value) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= _UINT64_MAX
    )


def _redeemer_pointer(tag, index) -> tuple[int, int]:
    if not _uint(tag) or tag not in set(_PURPOSE_TAGS.values()):
        raise_validation_error("Redeemer Purpose Is Invalid")
    if not _uint(index):
        raise_validation_error("Redeemer Index Is Invalid")
    return tag, index


def _execution_units(value) -> tuple[int, int]:
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise_validation_error("Redeemer Execution Units Are Invalid")
    memory, cpu = value
    if not _uint(memory) or not _uint(cpu):
        raise_validation_error("Redeemer Execution Units Are Invalid")
    return memory, cpu


def committed_redeemer_budgets(tx_cbor: str) -> dict[tuple[int, int], tuple[int, int]]:
    """Extract execution units committed by the submitted witness set.

    ``evaluateTransaction`` estimates what each script needs; it does not
    prove the execution units already encoded in the transaction are large
    enough. The script-integrity hash in the signed body binds these redeemers,
    so comparing the committed budgets to the estimate closes the otherwise
    straightforward phase-2 out-of-budget path.

    Both the Alonzo/Babbage list encoding and the Conway map encoding are
    accepted. Everything else fails locally before an upstream call.
    """
    try:
        transaction = cbor2.loads(bytes.fromhex(tx_cbor))
    except (ValueError, cbor2.CBORDecodeError):
        raise_validation_error("Invalid CBOR Data In Tx")
    if not isinstance(transaction, list) or len(transaction) != 4:
        raise_validation_error("Tx Must Have Four Elements")
    witness_set = transaction[1]
    if not isinstance(witness_set, dict):
        raise_validation_error("Witness Set Is Not A Dict")
    redeemers = witness_set.get(_REDEEMERS)
    if redeemers is None:
        raise_validation_error("Transaction Has No Redeemers")

    budgets: dict[tuple[int, int], tuple[int, int]] = {}
    if isinstance(redeemers, dict):
        entries = []
        for key, value in redeemers.items():
            if not isinstance(key, (list, tuple)) or len(key) != 2:
                raise_validation_error("Redeemer Pointer Is Invalid")
            if not isinstance(value, (list, tuple)) or len(value) != 2:
                raise_validation_error("Redeemer Value Is Invalid")
            entries.append((key[0], key[1], value[1]))
    elif isinstance(redeemers, list):
        entries = []
        for value in redeemers:
            if not isinstance(value, (list, tuple)) or len(value) != 4:
                raise_validation_error("Redeemer Value Is Invalid")
            entries.append((value[0], value[1], value[3]))
    else:
        raise_validation_error("Redeemers Are Not A Map Or List")

    if not entries:
        raise_validation_error("Transaction Has No Redeemers")
    for tag, index, execution_units in entries:
        pointer = _redeemer_pointer(tag, index)
        if pointer in budgets:
            raise_validation_error("Redeemer Pointer Is Duplicated")
        budgets[pointer] = _execution_units(execution_units)
    return budgets


def _evaluated_redeemer_budgets(
    evaluations: list,
) -> dict[tuple[int, int], tuple[int, int]] | None:
    budgets: dict[tuple[int, int], tuple[int, int]] = {}
    for evaluation in evaluations:
        if not _is_evaluation_result(evaluation):
            return None
        match = _VALIDATOR_POINTER_RE.fullmatch(evaluation["validator"])
        if match is None:
            return None
        pointer = (_PURPOSE_TAGS[match.group(1)], int(match.group(2)))
        if pointer in budgets or not _uint(pointer[1]):
            return None
        budget = evaluation["budget"]
        budgets[pointer] = (budget["memory"], budget["cpu"])
    return budgets


def check_valid_tx(
    tx_body_cbor: str,
    environment: str,
) -> None:
    """Ask Koios to perform phase-2 script evaluation.

    A non-empty, well-formed result proves the supplied Plutus context
    evaluated successfully at that upstream. It is not full phase-1 ledger
    validation or a balance check. Network/upstream failures surface as 503
    instead of being misreported as a bad-tx 400.

    Caller-supplied UTxOs are intentionally unsupported: an unsubmitted
    parent's output cannot be authenticated from a transaction reference
    alone, and Ogmios may prefer supplied values over ledger-resolved ones.
    """
    committed_budgets = committed_redeemer_budgets(tx_body_cbor)

    try:
        cost_models = get_protocol_cost_models(environment)
    except ProtocolParametersUnavailable as exc:
        logger.error("Protocol Parameters Unavailable: %s", exc)
        raise UpstreamServiceUnavailable() from exc

    try:
        script_data_hash_matches = verify_script_data_hash(
            tx_body_cbor, cost_models
        )
    except ScriptIntegrityError as exc:
        # The internal message names cursor mechanics ("truncated CBOR",
        # "transaction map key is duplicated"), which is operator vocabulary,
        # not caller vocabulary. Log it, and keep the wallet-facing string in
        # the repo's Title Case convention.
        logger.warning("Script data hash could not be established: %s", exc)
        raise_validation_error("Invalid Script Data Hash In Tx")
    if not script_data_hash_matches:
        raise_validation_error(
            "Script Data Hash Does Not Commit To Submitted Redeemers And Datums"
        )

    try:
        response = evaluate_transaction(tx_body_cbor, environment)
    except UpstreamUnavailable as exc:
        logger.error("Upstream Evaluation Unavailable: %s", exc)
        raise UpstreamServiceUnavailable() from exc
    if isinstance(response, dict) and "error" in response and "result" not in response:
        # Distinguish "the ledger rejected this transaction" from "we asked the
        # evaluator the wrong question". JSON-RPC reserves -32768..-32000 for
        # protocol-level faults: a KOIOS_URL pointing at a build without
        # evaluateTransaction answers -32601 Method Not Found over HTTP 200,
        # and reporting that as a 400 tells every wallet its transaction is bad
        # while the service is the broken party. Ogmios's own domain errors sit
        # outside that range and are real verdicts.
        error = response["error"]
        code = error.get("code") if isinstance(error, dict) else None
        if not isinstance(code, int) or isinstance(code, bool) or -32768 <= code <= -32000:
            logger.error("Upstream Evaluation Rejected The Request: %s", error)
            raise UpstreamServiceUnavailable()
        raise_validation_error("Transaction Fails Validation")
    if not (
        isinstance(response, dict)
        and response.get("jsonrpc") == "2.0"
        and isinstance(response.get("result"), list)
        and "error" not in response
        and response.get("method") == "evaluateTransaction"
    ):
        logger.error("Malformed Upstream Evaluation Response")
        raise UpstreamServiceUnavailable()

    evaluations = response["result"]
    if not evaluations:
        raise_validation_error("Transaction Has No Plutus Scripts To Evaluate")
    evaluated_budgets = _evaluated_redeemer_budgets(evaluations)
    if evaluated_budgets is None:
        logger.error("Malformed Upstream Evaluation Result")
        raise UpstreamServiceUnavailable()
    if evaluated_budgets.keys() != committed_budgets.keys():
        logger.error("Upstream Evaluation Redeemer Pointers Do Not Match Transaction")
        raise UpstreamServiceUnavailable()
    for pointer, required in evaluated_budgets.items():
        committed = committed_budgets[pointer]
        if committed[0] < required[0] or committed[1] < required[1]:
            raise_validation_error("Redeemer Execution Budget Is Too Small")
