#!/usr/bin/env python3
"""Differential fuzzer: this crate's hand-rolled CBOR decoder vs Python cbor2.

The Rust service must agree with `cbor2` about (a) whether a byte string
decodes at all and (b) exactly how many bytes one value consumes, because
`signature::tx_id` hashes the body's wire byte span and `script_integrity`
slices witness-set fields verbatim. A one-byte disagreement produces a witness
for the wrong transaction hash.

This driver generates inputs, feeds them to `examples/cbor_probe` (Rust) and to
`cbor2` (Python), renders both decodes in one canonical grammar, and records
every disagreement into `tests/fixtures/fuzz_divergences.json`. The Rust
regression suite `tests/cbor_differential_fuzz.rs` then replays that file
without Python.

Usage:
    source venv/bin/activate
    cargo build --release --example cbor_probe
    python3 rs/scripts/cbor_differential.py            # full run, fixed seed
    python3 rs/scripts/cbor_differential.py --quick    # ~77k inputs, smoke run
    python3 rs/scripts/cbor_differential.py --no-write # do not touch fixtures

See scripts/README.md for the grammar, the staged comparison, and the three
asymmetries between the two decoders that the grammar cannot express.
"""

from __future__ import annotations

import argparse
import io
import json
import math
import random
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

import cbor2
from cbor2 import CBORSimpleValue, CBORTag

RS_ROOT = Path(__file__).resolve().parent.parent
PROBE = RS_ROOT / "target" / "release" / "examples" / "cbor_probe"
CORPUS = RS_ROOT / "tests" / "fixtures" / "chain_corpus.json"
PYTHON_SUITE = RS_ROOT / "tests" / "fixtures" / "python_suite.json"
DIVERGENCES = RS_ROOT / "tests" / "fixtures" / "fuzz_divergences.json"

SEED = 20260809

# Tags cbor2 decodes semantically. The Rust decoder interprets only 2 and 3
# (bignums, which cbor2 also turns into ints), so full-structure comparison is
# restricted to inputs whose tags avoid this set minus {2, 3}. Measured by
# probing cbor2 with valid payloads for every tag in 0..300 plus 555, 1004,
# 55799, 65535 and 1000000.
CBOR2_SEMANTIC_TAGS = frozenset(
    {0, 1, 2, 3, 4, 5, 25, 28, 29, 30, 35, 36, 37, 100, 256, 258, 260, 261, 1004, 55799}
)
OPAQUE_TAGS = CBOR2_SEMANTIC_TAGS - {2, 3}

TAG_RE = re.compile(r"T(\d+)\(")
FLOAT_RE = re.compile(r"F([0-9a-f]{16})")

I128_MIN = -(2**127)
I128_MAX = 2**127 - 1


class Unrenderable(Exception):
    """cbor2 produced a type the canonical grammar has no spelling for."""


# --- canonical rendering of a cbor2 decode ---------------------------------


def render(value, out: list[str]) -> None:
    # bool before int: bool is a subclass of int in Python.
    if value is True:
        out.append("t")
    elif value is False:
        out.append("f")
    elif value is None:
        out.append("n")
    elif value is cbor2.undefined:
        out.append("u")
    elif isinstance(value, int):
        if I128_MIN <= value <= I128_MAX:
            out.append(f"i{value}")
        else:
            # Outside i128 the Rust decoder keeps the raw magnitude, so mirror
            # its sign-and-magnitude spelling: tag 3 encodes -1 - magnitude.
            magnitude = value if value > 0 else -1 - value
            out.append("I")
            out.append("+" if value > 0 else "-")
            out.append(format(magnitude, "X"))
    elif isinstance(value, float):
        out.append("F" + struct.pack(">d", value).hex())
    elif isinstance(value, bytes):
        out.append("b" + value.hex())
    elif isinstance(value, str):
        out.append("t" + value.encode("utf-8").hex())
    elif isinstance(value, CBORSimpleValue):
        out.append(f"s{value.value}")
    elif isinstance(value, CBORTag):
        out.append(f"T{value.tag}(")
        render(value.value, out)
        out.append(")")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            render(item, out)
        out.append("]")
    elif isinstance(value, dict) or type(value).__name__ == "FrozenDict":
        out.append("{")
        for index, (key, item) in enumerate(value.items()):
            if index:
                out.append(",")
            render(key, out)
            out.append(":")
            render(item, out)
        out.append("}")
    else:
        # datetime, Decimal, Fraction, set, Pattern, UUID, ... — only reachable
        # through a semantic tag, which the caller has already excluded from
        # structure comparison.
        raise Unrenderable(type(value).__name__)


def python_decode(data: bytes) -> str:
    """Decode with cbor2 and render in the canonical grammar.

    `V:<consumed>:<value>` on a comparable success, `S:<consumed>:<type>` when
    cbor2 accepted but produced a semantically decoded object the grammar has
    no spelling for (the byte span is still comparable), `E:<exception>` on
    rejection.
    """
    stream = io.BytesIO(data)
    try:
        value = cbor2.CBORDecoder(stream).decode()
    except Exception as exc:  # any failure at all means "rejected"
        return f"E:{type(exc).__name__}"
    consumed = stream.tell()
    out: list[str] = []
    try:
        render(value, out)
    except Unrenderable as exc:
        return f"S:{consumed}:{exc.args[0]}"
    except RecursionError:
        return f"S:{consumed}:RecursionError"
    return f"V:{consumed}:" + "".join(out)


def wire_tags(data: bytes) -> set[int]:
    """Every tag number that appears in `data`, by a structural byte scan.

    Independent of both decoders on purpose: the Rust rendering applies
    Python's duplicate-key collapse, which can drop a whole tagged subtree, and
    the cbor2 object no longer knows which tags it consumed. Best effort — the
    scan stops at the first malformed byte and returns what it found.
    """
    tags: set[int] = set()
    pos = 0
    stack: list[int | None] = [1]
    while stack:
        top = stack[-1]
        if top == 0:
            stack.pop()
            continue
        if top is None:
            if pos >= len(data):
                return tags
            if data[pos] == 0xFF:
                pos += 1
                stack.pop()
                continue
        else:
            stack[-1] = top - 1
        if pos >= len(data):
            return tags
        initial = data[pos]
        pos += 1
        major = initial >> 5
        info = initial & 0x1F
        if info < 24:
            argument: int | None = info
        elif info in (24, 25, 26, 27):
            width = {24: 1, 25: 2, 26: 4, 27: 8}[info]
            if pos + width > len(data):
                return tags
            argument = int.from_bytes(data[pos : pos + width], "big")
            pos += width
        elif info == 31:
            argument = None
        else:
            return tags

        if major in (0, 1, 7):
            if argument is None:
                return tags
        elif major in (2, 3):
            if argument is None:
                stack.append(None)
            else:
                pos += argument
                if pos > len(data):
                    return tags
        elif major == 4:
            stack.append(None if argument is None else argument)
        elif major == 5:
            stack.append(None if argument is None else argument * 2)
        else:  # major 6
            if argument is None:
                return tags
            tags.add(argument)
            stack.append(1)
    return tags


# --- input generators -------------------------------------------------------


def head(rng: random.Random, major: int, argument: int, width: int | None = None) -> bytes:
    """Emit a head for `major`/`argument`, optionally non-minimal."""
    if width is None:
        widths = [w for w in (0, 1, 2, 4, 8) if fits(argument, w)]
        width = rng.choice(widths)
    base = major << 5
    if width == 0:
        return bytes([base | argument])
    info = {1: 24, 2: 25, 4: 26, 8: 27}[width]
    return bytes([base | info]) + argument.to_bytes(width, "big")


def fits(argument: int, width: int) -> bool:
    if width == 0:
        return argument < 24
    return argument < (1 << (8 * width))


TEXT_ALPHABET = ["a", "z", "0", " ", "é", "€", "\U0001f600", "\x00", "~"]

TAG_CHOICES = [0, 1, 2, 3, 4, 24, 30, 42, 121, 258, 259, 1000, 55799, 65535, 4294967295]


def gen_item(rng: random.Random, depth: int) -> bytes:
    kinds = ["uint", "nint", "bytes", "text", "simple", "float", "tag"]
    if depth < 6:
        kinds += ["array", "array", "map", "map"]
    kind = rng.choice(kinds)

    if kind == "uint":
        return head(rng, 0, rng.choice([0, 1, 23, 24, 255, 256, 65535, 65536, 2**32 - 1]))
    if kind == "nint":
        return head(rng, 1, rng.choice([0, 1, 23, 24, 255, 256, 65535, 2**32 - 1]))
    if kind == "bytes":
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 12)))
        if rng.random() < 0.2:
            chunks = b"".join(
                head(rng, 2, len(part)) + part
                for part in (payload[:1], payload[1:])
                if True
            )
            return b"\x5f" + chunks + b"\xff"
        return head(rng, 2, len(payload)) + payload
    if kind == "text":
        text = "".join(rng.choice(TEXT_ALPHABET) for _ in range(rng.randrange(0, 6)))
        raw = text.encode("utf-8")
        if rng.random() < 0.2:
            first = text[:1].encode("utf-8")
            rest = text[1:].encode("utf-8")
            return (
                b"\x7f"
                + head(rng, 3, len(first))
                + first
                + head(rng, 3, len(rest))
                + rest
                + b"\xff"
            )
        return head(rng, 3, len(raw)) + raw
    if kind == "simple":
        return rng.choice(
            [
                b"\xf4",
                b"\xf5",
                b"\xf6",
                b"\xf7",
                b"\xe0",
                b"\xf0",
                b"\xf3",
                b"\xf8" + bytes([rng.randrange(256)]),
            ]
        )
    if kind == "float":
        return rng.choice(
            [
                b"\xf9" + bytes(rng.randrange(256) for _ in range(2)),
                b"\xfa" + bytes(rng.randrange(256) for _ in range(4)),
                b"\xfb" + bytes(rng.randrange(256) for _ in range(8)),
            ]
        )
    if kind == "tag":
        tag = rng.choice(TAG_CHOICES)
        if tag in (2, 3):
            magnitude = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 20)))
            inner = head(rng, 2, len(magnitude)) + magnitude
        else:
            inner = gen_item(rng, depth + 1) if depth < 6 else b"\x00"
        return head(rng, 6, tag) + inner
    if kind == "array":
        count = rng.randrange(0, 4)
        items = b"".join(gen_item(rng, depth + 1) for _ in range(count))
        if rng.random() < 0.3:
            return b"\x9f" + items + b"\xff"
        return head(rng, 4, count) + items
    # map
    count = rng.randrange(0, 4)
    entries = []
    for _ in range(count):
        if rng.random() < 0.25:
            key = gen_item(rng, depth + 1)
        else:
            key = rng.choice(
                [
                    head(rng, 0, rng.randrange(0, 25)),
                    head(rng, 1, rng.randrange(0, 5)),
                    b"\x41" + bytes([rng.randrange(256)]),
                    b"\x61\x61",
                ]
            )
        entries.append(key + gen_item(rng, depth + 1))
    body = b"".join(entries)
    if rng.random() < 0.3:
        return b"\xbf" + body + b"\xff"
    return head(rng, 5, count) + body


def mutate(rng: random.Random, data: bytes, edits: int) -> bytes:
    if not data:
        return data
    out = bytearray(data)
    for _ in range(edits):
        index = rng.randrange(len(out))
        out[index] = rng.randrange(256)
    return bytes(out)


def bitflip(rng: random.Random, data: bytes) -> bytes:
    if not data:
        return data
    out = bytearray(data)
    index = rng.randrange(len(out))
    out[index] ^= 1 << rng.randrange(8)
    return bytes(out)


def corner_cases() -> list[bytes]:
    """Deterministic sweep of the head-byte space and every half float."""
    cases: list[bytes] = []
    # Every possible initial byte, alone and followed by eight zero bytes.
    for first in range(256):
        cases.append(bytes([first]))
        cases.append(bytes([first]) + b"\x00" * 8)
    # Every half float.
    for bits in range(1 << 16):
        cases.append(b"\xf9" + bits.to_bytes(2, "big"))
    # Every simple value in the one-byte form.
    for value in range(256):
        cases.append(b"\xf8" + bytes([value]))
    # Head widths carrying the same argument, per major type.
    for major in range(8):
        for width in (0, 1, 2, 4, 8):
            for argument in (0, 1, 23, 24, 255, 256, 65535, 65536, 2**32 - 1, 2**64 - 1):
                if not fits(argument, width):
                    continue
                base = major << 5
                if width == 0:
                    raw = bytes([base | argument])
                else:
                    info = {1: 24, 2: 25, 4: 26, 8: 27}[width]
                    raw = bytes([base | info]) + argument.to_bytes(width, "big")
                cases.append(raw)
                cases.append(raw + b"\x00" * 4)
    # Indefinite containers, nesting, and stray breaks.
    for raw in [
        b"\xff",
        b"\x9f\xff",
        b"\xbf\xff",
        b"\xbf\x01\xff",
        b"\x9f\x01\xff",
        b"\x5f\xff",
        b"\x7f\xff",
        b"\x5f\x41\x01\xff",
        b"\x7f\x61\x61\xff",
        b"\x5f\x5f\x41\x01\xff\xff",
        # cbor2 stores its break_marker object as an ordinary item, value or
        # key inside a *definite* container; the Rust decoder rejects all of
        # these as a break with no open indefinite container.
        b"\x81\xff",
        b"\x82\x01\xff",
        b"\xa1\x01\xff",
        b"\xa1\xff\x01",
        b"\xa2\x01\xff\x02\xff",
        b"\xbf\xf9\x00\x00\x00\x04\xc1\x00\x00\xff\xff\xff",
        b"\x7f\x61\xc3\x61\xa8\xff",
        b"\x7f\x62\xc3\xa8\xff",
        b"\x62\xc3\x28",
        b"\xc2\x40",
        b"\xc3\x40",
        b"\xc2\x51" + b"\xff" * 17,
        b"\xc3\x51" + b"\xff" * 17,
        b"\xc2\x50" + b"\x7f" + b"\xff" * 15,
        b"\xc3\x50" + b"\x7f" + b"\xff" * 15,
        b"\xc2\x50" + b"\x80" + b"\x00" * 15,
        b"\xc3\x50" + b"\x80" + b"\x00" * 15,
        b"\xc2\x5f\x41\x01\xff",
        b"\xd9\x01\x02\x82\x01\x01",
        b"\xd9\x01\x02\x01",
        b"\xd9\xd9\xf7\x01",
        b"\xd8\x1c\x01",
        b"\xa2\x01\x02\x01\x03",
        # Python dict keys alias across types: True == 1, False == 0,
        # 1.0 == 1. Both orders, because the collapse keeps the first key's
        # slot and the last key's value.
        b"\xa2\x01\x02\xf5\x03",
        b"\xa2\xf5\x03\x01\x02",
        b"\xa2\x00\x02\xf4\x03",
        b"\xa2\xf4\x03\x00\x02",
        b"\xa2\x01\x02\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00\x03",
        b"\xa2\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00\x03\x01\x02",
        b"\xa2\x00\x02\xfb\x00\x00\x00\x00\x00\x00\x00\x00\x03",
        b"\xa1\xa0\x00",
        b"\xa1\x81\x00\x01",
        b"\x00\x00",
        b"",
    ]:
        cases.append(raw)
    # Depth: at the Rust cap, one past it, and cbor2's own ceiling.
    for depth in (1, 2, 23, 24, 255, 256, 257, 300):
        cases.append(b"\x9f" * depth + b"\x01" + b"\xff" * depth)
        cases.append(b"\x81" * depth + b"\x01")
    return cases


# --- probe plumbing ---------------------------------------------------------


def run_probe(hexes: list[str], scratch: Path) -> list[str]:
    payload = "\n".join(hexes) + "\n"
    infile = scratch / "probe_in.txt"
    infile.write_text(payload)
    with infile.open("rb") as stdin:
        result = subprocess.run(
            [str(PROBE)], stdin=stdin, capture_output=True, check=True
        )
    lines = result.stdout.decode().splitlines()
    if len(lines) != len(hexes):
        raise SystemExit(f"probe returned {len(lines)} lines for {len(hexes)} inputs")
    return lines


# --- comparison and classification -----------------------------------------


def normalize_nans(rendered: str) -> str:
    def swap(match: re.Match[str]) -> str:
        bits = int(match.group(1), 16)
        value = struct.unpack(">d", bits.to_bytes(8, "big"))[0]
        return "FNaN" if math.isnan(value) else match.group(0)

    return FLOAT_RE.sub(swap, rendered)


def opaque_tags_in(rendered: str) -> bool:
    return any(int(tag) in OPAQUE_TAGS for tag in TAG_RE.findall(rendered))


def classify(raw: bytes, rust: str, python: str) -> tuple[str, str, str]:
    """Return (class, verdict, why) for a disagreeing pair."""
    rust_ok = rust.startswith("V:")
    # "S:" means cbor2 accepted but returned a semantically decoded type, which
    # the grammar cannot spell — accepted, structure not comparable.
    python_ok = python.startswith(("V:", "S:"))
    opaque = bool(wire_tags(raw) & OPAQUE_TAGS)

    if rust_ok and not python_ok:
        if opaque:
            return (
                "semantic-tag-payload",
                "benign",
                "cbor2 runs a semantic decoder for this tag and rejects the payload; "
                "the Rust decoder keeps Value::Tag and defers rejection to the "
                "validator that reads the field.",
            )
        if python == "E:CBORDecodeValueError":
            return (
                "cbor2-value-check",
                "benign",
                "cbor2 applies a value-level check the Rust decoder leaves to the "
                "validators; both implementations still reject the transaction.",
            )
        return ("rust-accepts-cbor2-rejects", "REVIEW", "")

    if python_ok and not rust_ok:
        if rust == "E:Malformed(unexpected CBOR break)":
            return (
                "stray-break",
                "rust-stricter",
                "cbor2 hands back a break_marker object for a break with no open "
                "indefinite container; RFC 8949 says that is not well-formed and "
                "the Rust decoder rejects it.",
            )
        if rust == "E:DepthExceeded":
            return (
                "depth-cap",
                "rust-stricter",
                "MAX_DEPTH = 256 bounds recursion so a crafted payload cannot "
                "overflow the stack; cbor2 only fails around depth 500.",
            )
        if rust == "E:Malformed(non-minimal CBOR simple value)":
            return (
                "one-byte-simple-below-32",
                "rust-stricter",
                "RFC 8949 §3.3 declares the one-byte simple-value form ill-formed "
                "for arguments below 32, because those values have a single-byte "
                "spelling. cbor2 accepts f800..f81f as CBORSimpleValue; the Rust "
                "decoder rejects them. No Cardano transaction field is a major-7 "
                "simple value, so the only inputs affected are hand-crafted ones, "
                "and the divergence is in the rejecting direction.",
            )
        return ("rust-rejects-cbor2-accepts", "REVIEW", "")

    # Both accepted. The byte span is always comparable; the structure is not
    # when cbor2 ran a semantic decoder somewhere inside.
    rust_consumed = rust.split(":", 2)[1]
    python_consumed = python.split(":", 2)[1]
    if rust_consumed != python_consumed:
        return ("span-mismatch", "REVIEW", "byte span disagreement")

    if normalize_nans(rust) == normalize_nans(python):
        return (
            "nan-payload",
            "REVIEW",
            "The two decoders produced NaNs with different bit patterns. "
            "cbor::f16_to_f64 is supposed to reproduce cbor2's widening exactly, "
            "payload and quiet bit included, so this is a regression rather than "
            "a known difference.",
        )

    rust_body = rust.split(":", 2)[2]
    python_body = python.split(":", 2)[2]
    if rust_body.count(":") > python_body.count(":") and "{" in rust_body:
        return (
            "python-key-coercion",
            "benign",
            "A Python dict collapses map keys that compare equal across types "
            "(False == 0, True == 1, 1.0 == 1), so `body[0]` / `body[1]` can "
            "resolve to the aliased entry's value. Value::Map keeps both "
            "entries in wire order, so the canonical renderings differ. The "
            "*lookup* does not diverge: Value::map_get refuses to read a map "
            "that contains a bool or float key aliasing the requested integer, "
            "so the field reads as absent and the transaction is rejected "
            "rather than validated against a different value than Python would "
            "see. The ledger's own body decoder rejects such a body in phase 1 "
            "anyway.",
        )
    if opaque:
        return (
            "semantic-tag-value",
            "benign",
            "cbor2 replaced a tag with a decoded Python object; the Rust decoder "
            "keeps Value::Tag.",
        )
    return ("value-mismatch", "REVIEW", "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="~10k inputs instead of 200k+")
    parser.add_argument("--no-write", action="store_true", help="do not write the fixture")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--per-class", type=int, default=4, help="frozen cases per class")
    parser.add_argument(
        "--dump",
        default="",
        help="print the frozen cases of classes whose name or verdict contains this",
    )
    parser.add_argument(
        "--scratch",
        type=Path,
        default=Path("/tmp") / "cbor_differential",
        help="directory for the probe's stdin files",
    )
    args = parser.parse_args()

    if not PROBE.exists():
        raise SystemExit(
            f"{PROBE} missing — run: cargo build --release --example cbor_probe"
        )
    args.scratch.mkdir(parents=True, exist_ok=True)

    corpus = json.loads(CORPUS.read_text())["transactions"]
    suite = json.loads(PYTHON_SUITE.read_text())["transactions"]
    real = [bytes.fromhex(tx["cbor"]) for tx in corpus] + [
        bytes.fromhex(tx["cbor"]) for tx in suite
    ]

    scale = 0.05 if args.quick else 1.0
    plan = {
        "corner-sweep": None,  # deterministic, size fixed by corner_cases()
        "random-bytes": int(60_000 * scale),
        "structured": int(60_000 * scale),
        "structured-corrupted": int(40_000 * scale),
        "corpus-truncated": int(20_000 * scale),
        "corpus-mutated": int(20_000 * scale),
    }

    rng = random.Random(args.seed)
    started = time.time()
    counts: dict[str, int] = {}
    agreements = 0
    structural = 0  # inputs both sides decoded and whose structure was compared
    span_only = 0  # both decoded, span compared, structure not comparable
    classes: dict[str, dict] = {}
    frozen: list[dict] = []
    seen_hex: set[str] = set()
    seen_variants: set[tuple] = set()

    def batches(name: str, produce):
        pending: list[bytes] = []
        total = 0
        for raw in produce:
            pending.append(raw)
            if len(pending) >= 5000:
                total += consume(name, pending)
                pending = []
        if pending:
            total += consume(name, pending)
        counts[name] = total

    def consume(name: str, inputs: list[bytes]) -> int:
        nonlocal agreements, structural, span_only
        hexes = [raw.hex() for raw in inputs]
        rust_lines = run_probe(hexes, args.scratch)
        for hexed, raw, rust in zip(hexes, inputs, rust_lines, strict=True):
            python = python_decode(raw)
            rust_ok = rust.startswith("V:")
            python_ok = python.startswith(("V:", "S:"))

            # Stage 1: accept vs reject. Error spellings differ by design, so
            # two rejections agree whatever they say.
            if not rust_ok and not python_ok:
                agreements += 1
                continue
            # Stage 2: the byte span, always comparable when both accepted,
            # and the thing the signing path actually depends on.
            if rust_ok and python_ok and rust.split(":", 2)[1] == python.split(":", 2)[1]:
                # Stage 3: full structure, only when cbor2 ran no semantic
                # decoder anywhere in the input.
                comparable = python.startswith("V:") and not (wire_tags(raw) & OPAQUE_TAGS)
                if not comparable:
                    span_only += 1
                    agreements += 1
                    continue
                structural += 1
                if rust == python:
                    agreements += 1
                    continue

            klass, verdict, why = classify(raw, rust, python)
            entry = classes.setdefault(
                klass,
                {
                    "count": 0,
                    "verdict": verdict,
                    "why": why,
                    "generators": {},
                    "frozen": [],
                },
            )
            entry["count"] += 1
            entry["generators"][name] = entry["generators"].get(name, 0) + 1
            # Freeze one representative per distinct sub-shape rather than the
            # first N of a class, so the regression file covers every semantic
            # tag that diverges instead of five spellings of tag 0.
            tags = tuple(sorted(wire_tags(raw) & OPAQUE_TAGS))
            variant = (klass, tags) if tags else None
            if (
                (variant is None or variant not in seen_variants)
                and hexed not in seen_hex
                and len(entry["frozen"]) < args.per_class
            ):
                if variant is not None:
                    seen_variants.add(variant)
                seen_hex.add(hexed)
                entry["frozen"].append(hexed)
                frozen.append(
                    {
                        "hex": hexed,
                        "rust": rust,
                        "python": python,
                        "verdict": verdict,
                        "class": klass,
                        "generator": name,
                        "why": why,
                    }
                )
        return len(inputs)

    def gen_random_bytes(count: int):
        for _ in range(count):
            length = rng.randrange(1, 65)
            yield bytes(rng.randrange(256) for _ in range(length))

    def gen_structured(count: int):
        for _ in range(count):
            yield gen_item(rng, 0)

    def gen_structured_corrupted(count: int):
        for _ in range(count):
            yield mutate(rng, gen_item(rng, 0), rng.randint(1, 3))

    def gen_truncated(count: int):
        for _ in range(count):
            raw = rng.choice(real)
            yield raw[: rng.randrange(1, len(raw))]

    def gen_corpus_mutated(count: int):
        for _ in range(count):
            raw = rng.choice(real)
            yield bitflip(rng, raw) if rng.random() < 0.5 else mutate(rng, raw, 1)

    batches("corner-sweep", corner_cases())
    batches("random-bytes", gen_random_bytes(plan["random-bytes"]))
    batches("structured", gen_structured(plan["structured"]))
    batches("structured-corrupted", gen_structured_corrupted(plan["structured-corrupted"]))
    batches("corpus-truncated", gen_truncated(plan["corpus-truncated"]))
    batches("corpus-mutated", gen_corpus_mutated(plan["corpus-mutated"]))

    elapsed = time.time() - started
    total = sum(counts.values())

    print(f"inputs: {total} in {elapsed:.1f}s")
    for name, count in counts.items():
        print(f"  {name:>22}: {count}")
    print(f"agreements: {agreements}")
    print(f"both decoded, full structure compared: {structural}")
    print(f"both decoded, span compared only (semantic tag / type): {span_only}")
    print(f"divergence classes: {len(classes)}")
    for klass, info in sorted(classes.items(), key=lambda kv: -kv[1]["count"]):
        print(f"  {klass:>28} x{info['count']:<8} {info['verdict']}  {info['generators']}")

    if args.dump:
        for case in frozen:
            if args.dump in case["class"] or args.dump in case["verdict"]:
                print(f"\n  {case['class']} / {case['verdict']} / {case['generator']}")
                print(f"    hex    {case['hex']}")
                print(f"    rust   {case['rust'][:400]}")
                print(f"    python {case['python'][:400]}")

    if args.no_write:
        return 0

    frozen.sort(key=lambda case: (case["class"], case["hex"]))
    document = {
        "note": (
            "Divergences between this crate's CBOR decoder and Python cbor2, found "
            "by scripts/cbor_differential.py. Each case is frozen so "
            "tests/cbor_differential_fuzz.rs can replay it without Python. "
            "'rust' is the canonical rendering the crate produces today; 'python' "
            "is what cbor2 produced at capture time. Representative cases only: "
            f"up to {args.per_class} per class, with the full counts in 'classes'."
        ),
        "seed": args.seed,
        "inputs": total,
        "generators": counts,
        "agreements": agreements,
        "structure_compared": structural,
        "span_compared_only": span_only,
        "classes": {
            klass: {
                "count": info["count"],
                "verdict": info["verdict"],
                "why": info["why"],
                "generators": info["generators"],
            }
            for klass, info in sorted(classes.items())
        },
        "cases": frozen,
    }
    DIVERGENCES.write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {DIVERGENCES} ({len(frozen)} frozen cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
