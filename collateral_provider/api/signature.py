import binascii
import hashlib
import json
import os
from io import BytesIO
from threading import RLock

import cbor2
from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

_key_cache: dict[str, tuple[float, str]] = {}
_key_cache_lock = RLock()


def get_key_from_file(file_path: str) -> str:
    """Read a Cardano-CLI-style ``{"cborHex": "..."}`` key file and return
    the raw key bytes as hex. The leading 4 hex chars are the CBOR
    byte-string tag and are stripped.

    Cached by ``(path, mtime)``: a key rotation (atomic write of a new
    skey/vkey) is picked up on the next signing request without restarting
    the process. The hot-path cost is one ``os.path.getmtime`` syscall.
    Concurrent re-reads are serialized under a lock so two threads racing
    to load a freshly-rotated key don't both end up parsing the file.
    """
    mtime = os.path.getmtime(file_path)
    cached = _key_cache.get(file_path)
    if cached is not None and cached[0] == mtime:
        return cached[1]
    with _key_cache_lock:
        cached = _key_cache.get(file_path)
        if cached is not None and cached[0] == mtime:
            return cached[1]
        with open(file_path) as file:
            data = json.load(file)
        hex_value = data["cborHex"][4:]
        _key_cache[file_path] = (mtime, hex_value)
        return hex_value


def _clear_key_cache() -> None:
    """Test helper: drop the in-memory cache so a fresh tmp file gets read."""
    with _key_cache_lock:
        _key_cache.clear()


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


def _consume_array_header(stream: BytesIO) -> None:
    """Advance ``stream`` past a CBOR array header (any length encoding).

    Raises ``ValueError`` if the next byte isn't a CBOR major-type-4
    (array) header. Both definite-length encodings (1, 2, 3, 5, or 9
    header bytes) and the indefinite-length form (``0x9f``) are accepted;
    in the indefinite case the stream is left positioned at the first
    item, exactly as for definite-length, and the body element is then
    consumed by the caller's single ``CBORDecoder.decode()`` call.
    """
    initial = stream.read(1)
    if not initial:
        raise ValueError("Empty CBOR")
    byte = initial[0]
    if byte >> 5 != 4:
        raise ValueError(f"Expected CBOR array, got major type {byte >> 5}")
    info = byte & 0x1F
    if info < 24 or info == 31:
        return
    extra = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if extra is None:
        raise ValueError(f"Reserved CBOR array header info {info}")
    stream.read(extra)


def tx_id(tx_cbor: str) -> str:
    """Hash the body's exact byte slice from the input transaction CBOR.

    The chain validates vkey witnesses against
    ``blake2b(submitted_body_bytes)``: when a node receives a tx, it
    hashes the body bytes as they appear on the wire, not a
    re-serialization. To make our witness verify on submit, we have to
    hash the *same* bytes the client will submit — never anything we
    re-emit through cbor2. Re-emitting would only round-trip cleanly
    when cbor2's serialization choices (definite vs. indefinite
    lengths, integer widths, map-key ordering, set-tag presence) happen
    to coincide with the client's tx-builder, which isn't a contract
    we can rely on. Slicing the body byte-range out of the input
    sidesteps the whole problem: whatever the client built, we hash
    that.

    The transaction is encoded as a 4-element CBOR array
    ``[body, witness_set, is_valid, auxiliary_data]``. We advance past
    the outer array header, snapshot the stream offset, decode exactly
    one item (the body), then read the offset again — the difference
    is the body's byte span.
    """
    tx_bytes = bytes.fromhex(tx_cbor)
    stream = BytesIO(tx_bytes)
    _consume_array_header(stream)
    body_start = stream.tell()
    cbor2.CBORDecoder(stream).decode()
    body_end = stream.tell()
    return hashlib.blake2b(tx_bytes[body_start:body_end], digest_size=32).hexdigest()


def create_witness_cbor(public_key: str, signature: str) -> str:
    """Build a Cardano vkey-witness CBOR: cbor([0, [pubkey, signature]])."""
    return cbor2.dumps(
        [0, [binascii.unhexlify(public_key), binascii.unhexlify(signature)]]
    ).hex()


def witness_tx_cbor(tx_cbor: str, skey_path: str, vkey_path: str) -> tuple[str, str]:
    """Hash the body, sign it with the on-disk skey, return ``(witness_cbor, tx_hash)``.

    The tx hash is exposed so callers can log it on success — operators
    can grep "did we sign tx X" in structured logs without needing the
    request id from the original caller.
    """
    sk = get_key_from_file(skey_path)
    pk = get_key_from_file(vkey_path)
    tx_hash = tx_id(tx_cbor)
    sig = sign(sk, tx_hash)
    return create_witness_cbor(pk, sig), tx_hash
