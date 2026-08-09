from io import BytesIO

import cbor2
from django.conf import settings

from api.ban_list import banned_addresses
from api.tx_fields import (
    COLLATERAL_INPUTS,
    COLLATERAL_RETURN,
    INPUTS,
    OUTPUTS,
    REQUIRED_SIGNERS,
    SET_TAG,
    TX_BODY,
    TX_IS_VALID,
)
from api.util import raise_validation_error


def _set_items(value) -> list | None:
    """Normalize a CDDL ``set<T>`` body field into a list of entries.

    Conway permits both encodings — ``set<a0> = #6.258([* a0]) / [* a0]``
    (eras/conway/impl/cddl/data/conway.cddl). cbor2 decodes the tagged form
    to a Python ``set`` (turning nested arrays into tuples) and the untagged
    form to a ``list`` of ``list``s. Gating on ``isinstance(x, set)`` alone
    therefore rejects a legal encoding, so normalize the container *and* its
    entries here and let every caller work against one shape.

    Entries are de-duplicated so the untagged form carries the same semantics
    as the tagged one, where the decoder collapses duplicates for us.

    Returns ``None`` when the value is neither encoding.
    """
    if isinstance(value, cbor2.CBORTag):
        if value.tag != SET_TAG:
            return None
        value = value.value
    if isinstance(value, (set, frozenset)):
        entries = list(value)
    elif isinstance(value, list):
        entries = value
    else:
        return None

    normalized: list = []
    seen: set = set()
    for entry in entries:
        item = tuple(entry) if isinstance(entry, list) else entry
        try:
            if item in seen:
                continue
            seen.add(item)
        except TypeError:
            # Unhashable entry — keep it so the shape check below rejects it
            # with a specific message instead of failing here.
            pass
        normalized.append(item)
    return normalized


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
    stream = BytesIO(tx_bytes)
    try:
        tx = cbor2.CBORDecoder(stream).decode()
    except cbor2.CBORDecodeError:
        raise_validation_error("Invalid CBOR Data In Tx")
    if not isinstance(tx, list):
        raise_validation_error("Tx Is Not A List")
    if stream.read(1):
        raise_validation_error("Trailing Data After Tx")
    if len(tx) != 4:
        raise_validation_error("Tx Must Have Four Elements")

    body = tx[TX_BODY]
    if not isinstance(body, dict):
        raise_validation_error("Tx Body Is Not A Dict")

    if not isinstance(tx[1], dict):
        raise_validation_error("Witness Set Is Not A Dict")

    is_valid = tx[TX_IS_VALID]
    if not isinstance(is_valid, bool):
        raise_validation_error("Boolean Is Not A Bool")
    if is_valid is False:
        raise_validation_error("Boolean Can't Be False")

    return body


def check_inputs(body: dict, env_settings: dict) -> None:
    """Reject any tx whose regular inputs include the collateral UTxO —
    that would consume it instead of just locking it as collateral."""
    if INPUTS not in body:
        raise_validation_error("Inputs Does Not Exist In Body")
    inputs = _set_items(body[INPUTS])
    if inputs is None:
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
    collaterals = _set_items(body[COLLATERAL_INPUTS])
    if collaterals is None:
        raise_validation_error("Collateral Is Not A Set")
    if len(collaterals) != 1:
        raise_validation_error("Exactly One Collateral Input Is Required")

    expected_txid = env_settings["TXID"]
    expected_idx = env_settings["TXIDX"]
    for utxo in collaterals:
        _check_utxo_shape(utxo)
        if utxo[0].hex() == expected_txid and int(utxo[1]) == expected_idx:
            return
    raise_validation_error("Collateral Is Not Being Used In Tx")


def check_collateral_return(body: dict, pkh: str) -> None:
    """If the tx sets CIP-40 collateral return, require it to pay us back.

    Body field 16 is consulted by the ledger only on the phase-2-invalid
    branch, so it cannot make a script fail and is not itself a route to
    losing the collateral. What it decides is *who receives the remainder*
    when the collateral is consumed. Left unchecked, an attacker names their
    own address and keeps roughly the collateral minus the covered fee, which
    turns a break-even griefing attack into a profitable one.

    The field stays optional so builders that omit it are unaffected. When
    present, the payment credential must be this provider's key hash.

    A Shelley address is ``header || payment_credential[28] || ...``. The
    high nibble of the header selects the address type; even types carry a
    key-hash payment credential, odd types a script hash.
    """
    if COLLATERAL_RETURN not in body:
        return
    utxo = body[COLLATERAL_RETURN]
    if not isinstance(utxo, (list, dict)):
        raise_validation_error("Collateral Return Is Not A List Or Dict")
    try:
        address = utxo[0]
    except (IndexError, KeyError):
        raise_validation_error("Collateral Return Has No Address")
    if not isinstance(address, bytes) or len(address) < 29:
        raise_validation_error("Collateral Return Address Is Malformed")
    if (address[0] >> 4) % 2 != 0:
        raise_validation_error("Collateral Return Must Not Pay A Script Address")
    if address[1:29].hex() != pkh:
        raise_validation_error("Collateral Return Must Pay The Collateral Provider")


def check_signers(body: dict, pkh: str) -> None:
    """Require that this provider's PKH is in required_signers — a tx that
    doesn't list us as a signer cannot legitimately consume our witness."""
    if REQUIRED_SIGNERS not in body:
        raise_validation_error("Required Signers Does Not Exist In Body")
    signers = _set_items(body[REQUIRED_SIGNERS])
    if signers is None:
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
    if len(utxo) != 2:
        raise_validation_error("UTxO Must Have Two Elements")
    if not isinstance(utxo[0], bytes):
        raise_validation_error("TxId Is Not Bytes")
    if len(utxo[0]) != 32:
        raise_validation_error("TxId Must Be 32 Bytes")
    if not isinstance(utxo[1], int) or isinstance(utxo[1], bool):
        raise_validation_error("TxIdx Is Not An Int")
    if utxo[1] < 0:
        raise_validation_error("TxIdx Can't Be Negative")
