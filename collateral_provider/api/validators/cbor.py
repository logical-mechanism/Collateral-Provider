import cbor2
from django.conf import settings

from api.ban_list import banned_addresses
from api.tx_fields import (
    COLLATERAL_INPUTS,
    INPUTS,
    OUTPUTS,
    REQUIRED_SIGNERS,
    TX_BODY,
    TX_IS_VALID,
)
from api.util import raise_validation_error


def check_cbor_hex(tx_body_cbor: str) -> bytes:
    """Decode the hex envelope and enforce the on-chain max tx size."""
    if not tx_body_cbor:
        raise_validation_error("Tx Can't Be Empty")
    try:
        tx_bytes = bytes.fromhex(tx_body_cbor)
    except ValueError:
        raise_validation_error("Invalid Hex Data In Tx")
    if len(tx_bytes) > settings.MAX_TX_SIZE:
        raise_validation_error("Tx Is Too Large")
    return tx_bytes


def check_tx_body(tx_bytes: bytes) -> dict:
    """Decode the outer CBOR envelope and return the inner body map.

    Validates that the envelope is a list, that the is_valid flag is True
    (an explicit False would direct the chain to consume the collateral —
    we refuse to sign such transactions), and that the body slot is a map.
    """
    try:
        tx = cbor2.loads(tx_bytes)
    except cbor2.CBORDecodeError:
        raise_validation_error("Invalid CBOR Data In Tx")
    if not isinstance(tx, list):
        raise_validation_error("Tx Is Not A List")

    try:
        is_valid = tx[TX_IS_VALID]
    except IndexError:
        raise_validation_error("Boolean Does Not Exist In Tx")
    if not isinstance(is_valid, bool):
        raise_validation_error("Boolean Is Not A Bool")
    if is_valid is False:
        raise_validation_error("Boolean Can't Be False")

    try:
        body = tx[TX_BODY]
    except IndexError:
        raise_validation_error("Body Does Not Exist In Tx")
    if not isinstance(body, dict):
        raise_validation_error("Tx Body Is Not A Dict")
    return body


def check_inputs(body: dict, env_settings: dict) -> None:
    """Reject any tx whose regular inputs include the collateral UTxO —
    that would consume it instead of just locking it as collateral."""
    if INPUTS not in body:
        raise_validation_error("Inputs Does Not Exist In Body")
    inputs = body[INPUTS]
    if not isinstance(inputs, set):
        raise_validation_error("Inputs Are Not A Set")

    expected_txid = env_settings["TXID"]
    expected_idx = env_settings["TXIDX"]
    for utxo in inputs:
        _check_utxo_shape(utxo)
        if utxo[0].hex() == expected_txid and int(utxo[1]) == expected_idx:
            raise_validation_error("Collateral Is Being Spent In Tx")


def check_outputs(body: dict) -> None:
    """Reject txs that send funds to addresses on the manual ban list.

    `utxo[0]` works for both Shelley list-encoded outputs (where 0 is the
    address slot) and Babbage map-encoded outputs (where 0 is the address
    map key). Both shapes therefore fall through the same check.
    """
    if OUTPUTS not in body:
        raise_validation_error("Outputs Does Not Exist In Body")
    outputs = body[OUTPUTS]
    if not isinstance(outputs, list):
        raise_validation_error("Outputs Are Not A List")

    for utxo in outputs:
        if not isinstance(utxo, (list, dict)):
            raise_validation_error("UTxO Is Not A List Or Dict")
        try:
            address = utxo[0]
        except (IndexError, KeyError):
            raise_validation_error("TxId Does Not Exist In UTxO")
        if not isinstance(address, bytes):
            raise_validation_error("TxId Is Not Bytes")
        if address.hex() in banned_addresses:
            raise_validation_error(f"The Address: {address.hex()} Is Banned")


def check_collateral(body: dict, env_settings: dict) -> None:
    """Require that this provider's collateral UTxO is referenced in the
    collateral_inputs set."""
    if COLLATERAL_INPUTS not in body:
        raise_validation_error("Collateral Does Not Exist In Body")
    collaterals = body[COLLATERAL_INPUTS]
    if not isinstance(collaterals, set):
        raise_validation_error("Collateral Is Not A Set")

    expected_txid = env_settings["TXID"]
    expected_idx = env_settings["TXIDX"]
    for utxo in collaterals:
        _check_utxo_shape(utxo)
        if utxo[0].hex() == expected_txid and int(utxo[1]) == expected_idx:
            return
    raise_validation_error("Collateral Is Not Being Used In Tx")


def check_signers(body: dict, pkh: str) -> None:
    """Require that this provider's PKH is in required_signers — a tx that
    doesn't list us as a signer cannot legitimately consume our witness."""
    if REQUIRED_SIGNERS not in body:
        raise_validation_error("Required Signers Does Not Exist In Body")
    signers = body[REQUIRED_SIGNERS]
    if not isinstance(signers, set):
        raise_validation_error("Required Signers Is Not A Set")

    for signer in signers:
        if not isinstance(signer, bytes):
            raise_validation_error("Tx Signer Is Not Bytes")
        if signer.hex() == pkh:
            return
    raise_validation_error("Collateral Public Key Hash Is Not Being Used")


def _check_utxo_shape(utxo) -> None:
    if not isinstance(utxo, tuple):
        raise_validation_error("UTxO Is Not A Tuple")
    try:
        utxo[0]
    except IndexError:
        raise_validation_error("TxId Does Not Exist In UTxO")
    if not isinstance(utxo[0], bytes):
        raise_validation_error("TxId Is Not Bytes")
    try:
        utxo[1]
    except IndexError:
        raise_validation_error("TxIdx Does Not Exist In UTxO")
    if not isinstance(utxo[1], int):
        raise_validation_error("TxIdx Is Not An Int")
