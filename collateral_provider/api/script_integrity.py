"""Cardano script-data-hash verification without a ledger SDK dependency.

The script data hash in transaction-body field 11 commits to the *original
CBOR bytes* of the redeemers and datums in the witness set, followed by the
language views derived from the protocol cost models.  Re-encoding decoded
values is not equivalent: the ledger deliberately memoizes the original
bytes for this calculation.

This module therefore contains a small, bounded-by-input-size CBOR cursor
which slices witness fields 4 and 5 from the submitted transaction verbatim.
It delegates decoding/skipping individual values to cbor2 rather than trying
to implement a second general-purpose CBOR decoder.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping, Sequence
from io import BytesIO
from itertools import combinations

import cbor2

_SCRIPT_DATA_HASH = 11
_DATUMS = 4
_REDEEMERS = 5
_SET_TAG = 258
_BREAK = 0xFF
_MAX_LANGUAGE = 3  # PlutusV1 through PlutusV4


class ScriptIntegrityError(ValueError):
    """The transaction cannot be used to establish script-data binding."""


class _CborCursor:
    """Track byte offsets while cbor2 handles individual CBOR values."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise ScriptIntegrityError("truncated CBOR")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def container_length(self, expected_major: int) -> int | None:
        """Read an array/map header and return its length (None = indefinite)."""
        initial = self._read_byte()
        major = initial >> 5
        additional = initial & 0x1F
        if major != expected_major:
            name = "array" if expected_major == 4 else "map"
            raise ScriptIntegrityError(f"expected CBOR {name}")
        if additional < 24:
            return additional
        byte_lengths = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional in byte_lengths:
            byte_length = byte_lengths[additional]
            end = self.pos + byte_length
            if end > len(self.data):
                raise ScriptIntegrityError("truncated CBOR container length")
            length = int.from_bytes(self.data[self.pos:end], "big")
            self.pos = end
            return length
        if additional == 31:
            return None
        raise ScriptIntegrityError("invalid CBOR container length")

    def at_break(self) -> bool:
        return self.pos < len(self.data) and self.data[self.pos] == _BREAK

    def consume_break(self) -> None:
        if not self.at_break():
            raise ScriptIntegrityError("missing CBOR break")
        self.pos += 1

    def decode_one(self):
        stream = BytesIO(self.data)
        stream.seek(self.pos)
        try:
            value = cbor2.CBORDecoder(stream).decode()
        except (
            cbor2.CBORDecodeError,
            EOFError,
            OverflowError,
            TypeError,
            ValueError,
        ) as exc:
            raise ScriptIntegrityError("invalid CBOR value") from exc
        end = stream.tell()
        if end <= self.pos:
            raise ScriptIntegrityError("invalid empty CBOR value")
        self.pos = end
        return value

    def raw_one(self) -> tuple[object, bytes]:
        start = self.pos
        value = self.decode_one()
        return value, self.data[start:self.pos]


def _map_items(cursor: _CborCursor):
    """Yield a map's decoded keys and raw value bytes, rejecting duplicates."""
    length = cursor.container_length(5)
    seen: set[int] = set()
    remaining = length
    while remaining is None or remaining > 0:
        if remaining is None and cursor.at_break():
            cursor.consume_break()
            return
        key = cursor.decode_one()
        if not isinstance(key, int) or isinstance(key, bool):
            raise ScriptIntegrityError("transaction map key is not an integer")
        if key in seen:
            raise ScriptIntegrityError("transaction map key is duplicated")
        seen.add(key)
        value, raw = cursor.raw_one()
        yield key, value, raw
        if remaining is not None:
            remaining -= 1
    if length is None:
        raise ScriptIntegrityError("missing CBOR map break")


def _datum_bytes(value: object, raw: bytes) -> bytes:
    """The ledger omits TxDats bytes when the decoded collection is empty."""
    if isinstance(value, cbor2.CBORTag) and value.tag == _SET_TAG:
        value = value.value
    if isinstance(value, (list, tuple, dict, set, frozenset)) and not value:
        return b""
    return raw


def script_data_parts(tx_cbor_hex: str) -> tuple[bytes, bytes, bytes]:
    """Return ``(body hash, raw redeemers, raw non-empty datums)``.

    Only the transaction envelope and the two relevant maps are traversed.
    The caller's normal transaction validators remain responsible for the
    rest of the transaction schema.
    """
    try:
        data = bytes.fromhex(tx_cbor_hex)
    except (TypeError, ValueError) as exc:
        raise ScriptIntegrityError("transaction is not hexadecimal CBOR") from exc

    cursor = _CborCursor(data)
    tx_length = cursor.container_length(4)
    if tx_length not in (4, None):
        raise ScriptIntegrityError("transaction must have four elements")

    committed_hash = None
    for key, value, _raw in _map_items(cursor):
        if key == _SCRIPT_DATA_HASH:
            committed_hash = value

    redeemers = None
    datums = b""
    for key, value, raw in _map_items(cursor):
        if key == _REDEEMERS:
            redeemers = raw
        elif key == _DATUMS:
            datums = _datum_bytes(value, raw)

    # is_valid and auxiliary_data
    cursor.decode_one()
    cursor.decode_one()
    if tx_length is None:
        cursor.consume_break()
    if cursor.pos != len(data):
        raise ScriptIntegrityError("transaction has trailing CBOR data")

    if not isinstance(committed_hash, bytes) or len(committed_hash) != 32:
        raise ScriptIntegrityError("transaction has no valid script data hash")
    if redeemers is None:
        raise ScriptIntegrityError("transaction has no redeemers")
    return committed_hash, redeemers, datums


def _validate_cost_models(
    cost_models: Mapping[int, Sequence[int]],
) -> dict[int, tuple[int, ...]]:
    if not isinstance(cost_models, Mapping) or not cost_models:
        raise ScriptIntegrityError("protocol cost models are empty")
    normalized: dict[int, tuple[int, ...]] = {}
    for language, costs in cost_models.items():
        if (
            not isinstance(language, int)
            or isinstance(language, bool)
            or not 0 <= language <= _MAX_LANGUAGE
        ):
            raise ScriptIntegrityError("protocol cost model language is invalid")
        if (
            not isinstance(costs, Sequence)
            or isinstance(costs, (str, bytes, bytearray))
            or not costs
        ):
            raise ScriptIntegrityError("protocol cost model is invalid")
        model: list[int] = []
        for parameter in costs:
            if (
                not isinstance(parameter, int)
                or isinstance(parameter, bool)
                or not -(1 << 63) <= parameter < (1 << 63)
            ):
                raise ScriptIntegrityError("protocol cost model parameter is invalid")
            model.append(parameter)
        normalized[language] = tuple(model)
    return normalized


def _language_view_pair(language: int, costs: Sequence[int]) -> tuple[bytes, bytes]:
    if language == 0:
        # PlutusV1 preserves the original Alonzo encoding bug: its language
        # key and indefinite-length parameter list are each wrapped in a CBOR
        # byte string (the historical "double-bagging").
        key = cbor2.dumps(cbor2.dumps(language))
        indefinite_costs = b"\x9f" + b"".join(cbor2.dumps(v) for v in costs) + b"\xff"
        value = cbor2.dumps(indefinite_costs)
        return key, value
    return cbor2.dumps(language), cbor2.dumps(list(costs))


def encode_language_views(cost_models: Mapping[int, Sequence[int]]) -> bytes:
    """Encode the ledger language-view map for one selected model subset."""
    normalized = _validate_cost_models(cost_models)
    pairs = [_language_view_pair(language, costs) for language, costs in normalized.items()]
    # The ledger orders the already-encoded keys using canonical CBOR shortlex
    # ordering.  This notably places V2/V3/V4 before V1 in a mixed map.
    pairs.sort(key=lambda pair: (len(pair[0]), pair[0]))
    if len(pairs) >= 24:  # Currently impossible, but keep the encoder honest.
        raise ScriptIntegrityError("too many protocol cost models")
    return bytes((0xA0 + len(pairs),)) + b"".join(key + value for key, value in pairs)


def calculate_script_data_hash(
    redeemers: bytes,
    datums: bytes,
    cost_models: Mapping[int, Sequence[int]],
) -> bytes:
    """Calculate a script data hash from exact witness bytes and models."""
    language_views = encode_language_views(cost_models)
    return hashlib.blake2b(
        redeemers + datums + language_views,
        digest_size=32,
    ).digest()


def verify_script_data_hash(
    tx_cbor_hex: str,
    cost_models: Mapping[int, Sequence[int]],
) -> bool:
    """Check field 11 against every possible current language-model subset.

    The language set cannot be determined from the witness set alone because
    scripts may be supplied by reference inputs.  Trying all non-empty
    subsets still proves that the submitted redeemers/datums are what field
    11 commits to; a wrong subset is rejected later by ledger phase-1 checks.
    With four supported Plutus versions this is at most 15 hashes.
    """
    committed_hash, redeemers, datums = script_data_parts(tx_cbor_hex)
    normalized = _validate_cost_models(cost_models)
    languages = sorted(normalized)
    matched = False
    for count in range(1, len(languages) + 1):
        for selected in combinations(languages, count):
            subset = {language: normalized[language] for language in selected}
            candidate = calculate_script_data_hash(redeemers, datums, subset)
            matched |= hmac.compare_digest(committed_hash, candidate)
    return matched
