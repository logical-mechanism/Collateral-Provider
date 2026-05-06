import binascii
import hashlib
import json
from functools import lru_cache

import cbor2
from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from api.tx_fields import (
    CERTIFICATES,
    COLLATERAL_INPUTS,
    INPUTS,
    PROPOSAL_PROCEDURES,
    REFERENCE_INPUTS,
    REQUIRED_SIGNERS,
    SET_TAG,
    TX_BODY,
)

# Body fields that are CBOR-tag-258 sets in Conway. Their contents must be
# sorted and re-tagged before hashing — anything else produces a tx-id the
# node will reject.
_SET_BODY_FIELDS = (
    INPUTS,
    CERTIFICATES,
    COLLATERAL_INPUTS,
    REQUIRED_SIGNERS,
    REFERENCE_INPUTS,
    PROPOSAL_PROCEDURES,
)


def _ordered_set(items) -> cbor2.CBORTag:
    return cbor2.CBORTag(SET_TAG, sorted(items))


@lru_cache(maxsize=4)
def get_key_from_file(file_path: str) -> str:
    """Read a Cardano-CLI-style {"cborHex": "..."} key file and return the raw
    key bytes as hex. The leading 4 hex chars are the CBOR byte-string tag and
    are stripped so callers get just the key material.

    Cached per-path because the keys never change during process lifetime.
    Without the cache we'd open + json-decode the skey on every request."""
    with open(file_path) as file:
        data = json.load(file)
    return data["cborHex"][4:]


def sign(skey: str, msg: str) -> str:
    """Ed25519-sign a hex message with a hex secret key, return hex signature."""
    sk_bytes = bytes.fromhex(skey)
    msg_bytes = bytes.fromhex(msg)
    signing_key = SigningKey(sk_bytes)
    return signing_key.sign(msg_bytes, encoder=RawEncoder).signature.hex()


def verify(vkey: str, signature: str, msg: str) -> bool:
    """Ed25519-verify a hex signature against a hex message and hex public key."""
    vk_bytes = bytes.fromhex(vkey)
    sig_bytes = bytes.fromhex(signature)
    msg_bytes = bytes.fromhex(msg)

    verify_key = VerifyKey(vk_bytes, encoder=RawEncoder)
    try:
        verify_key.verify(msg_bytes, sig_bytes, encoder=RawEncoder)
        return True
    except BadSignatureError:
        return False


def tx_id(tx_cbor: str) -> str:
    """Compute the Blake2b-256 hash of the canonicalized transaction body."""
    tx_bytes = bytes.fromhex(tx_cbor)
    tx = cbor2.loads(tx_bytes)
    body = tx[TX_BODY]

    for idx in _SET_BODY_FIELDS:
        if idx in body:
            body[idx] = _ordered_set(body[idx])

    body_cbor = cbor2.dumps(body)
    return hashlib.blake2b(body_cbor, digest_size=32).hexdigest()


def create_witness_cbor(public_key: str, signature: str) -> str:
    """Build a Cardano vkey-witness CBOR: cbor([0, [pubkey, signature]])."""
    return cbor2.dumps(
        [0, [binascii.unhexlify(public_key), binascii.unhexlify(signature)]]
    ).hex()


def witness_tx_cbor(tx_cbor: str, skey_path: str, vkey_path: str) -> str:
    """Hash the body, sign it with the on-disk skey, return the witness CBOR."""
    sk = get_key_from_file(skey_path)
    pk = get_key_from_file(vkey_path)
    tx_hash = tx_id(tx_cbor)
    sig = sign(sk, tx_hash)
    return create_witness_cbor(pk, sig)
