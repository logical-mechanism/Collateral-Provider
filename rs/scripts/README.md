# CBOR differential fuzzer

`cbor_differential.py` fuzzes this crate's hand-rolled CBOR decoder
(`src/cbor.rs`) against Python's `cbor2` — the library the Django service
decodes transactions with, and therefore the behavioural reference this port
has to match.

Why it matters: `signature::tx_id` hashes the transaction body's *exact wire
byte span*, and `script_integrity` slices witness-set fields 4 and 5 verbatim.
A decoder that consumes one byte too many produces a witness for a transaction
hash that does not exist. Structural unit tests do not catch that; a
byte-for-byte comparison against a second implementation does.

## Running it

```bash
source venv/bin/activate                              # needs cbor2
cd rs
cargo build --release --example cbor_probe
python3 scripts/cbor_differential.py                  # full run, ~5s
python3 scripts/cbor_differential.py --quick          # ~77k inputs, smoke run
python3 scripts/cbor_differential.py --no-write       # do not touch fixtures
python3 scripts/cbor_differential.py --dump REVIEW    # print unexplained cases
```

The run is deterministic: `--seed` defaults to `20260809` and every generator
draws from one seeded `random.Random`. Same seed, same inputs, same result.

Output goes to `tests/fixtures/fuzz_divergences.json`, which
`tests/cbor_differential_fuzz.rs` replays **without Python** — that file is the
regression suite, this script is the tool that produced it.

## How the comparison works

`examples/cbor_probe` reads one hex input per line on stdin and writes one
result line per input. The Python driver renders `cbor2`'s decode of the same
bytes into the identical grammar and compares the strings.

```text
E:<variant>                     decode error
V:<consumed>:<canonical value>  decode success
```

Canonical value grammar, emitted identically by both sides:

| kind | rendering |
|------|-----------|
| int | `i<decimal>` |
| bigint | `I<+\|-><uppercase hex magnitude, no leading zeros>` |
| bytes | `b<lowercase hex>` |
| text | `t<lowercase hex of the UTF-8 bytes>` |
| array | `[v1,v2,...]` |
| map | `{k1:v1,k2:v2,...}` |
| tag | `T<n>(<value>)` |
| false / true / null / undefined | `f` / `t` / `n` / `u` |
| simple | `s<n>` |
| float | `F<16 hex chars of the f64 bit pattern>` |

Comparison runs in three stages, so a difference the grammar cannot express
never suppresses the checks that still apply:

1. **Accept vs reject.** Always compared. The error *spellings* differ by
   design (`E:Truncated` vs `E:CBORDecodeEOF`), so two rejections agree
   whatever they say.
2. **Byte span.** Always compared when both accept. This is the check the
   signing path depends on, and it holds even for inputs whose structure is not
   comparable.
3. **Full structure.** Compared when `cbor2` ran no semantic tag decoder
   anywhere in the input.

## The asymmetries, and what is done about each

### 1. `cbor2` collapses duplicate map keys

`cbor2` builds a Python `dict`, so a repeated key silently overwrites the
earlier entry and the wire order and duplicates are gone. `cbor::Value::Map`
keeps every entry in wire order, which `script_integrity` needs.

*Handled by* rendering the Rust map with the same collapse **for the comparison
only** — first occurrence keeps its slot, last occurrence supplies the value.
What the collapse hides is covered by a non-differential test:
`map_wire_order_and_duplicates_survive_decoding` in
`tests/cbor_differential_fuzz.rs`.

There is a residue the collapse cannot paper over: Python compares dict keys
with `==`, so `False == 0`, `True == 1` and `1.0 == 1` alias, while the
canonical rendering keys on the spelling. That surfaces as the
`python-key-coercion` class rather than being hidden. See below — and note that
`Value::map_get` refuses such a map outright, so the divergence stays in the
rendering and never reaches a field lookup.

### 2. `cbor2` decodes some tags semantically

Measured, not assumed — every tag in `0..300` plus `555`, `1004`, `55799`,
`65535` and `1000000` was probed with valid payloads. `cbor2` transforms or
rejects:

```
0 1 2 3 4 5 25 28 29 30 35 36 37 100 256 258 260 261 1004 55799
```

The Rust decoder interprets only the bignum tags 2 and 3, which `cbor2` also
turns into `int`, so those two agree. Everything else stays a `Value::Tag` for
the validator that reads the field to reject.

*Handled by* restricting stage 3 (full structure) to inputs whose tags avoid
that set minus `{2, 3}`. Stages 1 and 2 still apply. The tag set is collected
by `wire_tags()`, an independent structural byte scan — **not** by reading tags
out of either decoder's output, because the duplicate-key collapse can drop a
whole tagged subtree from the rendering. `wire_tags` is validated against the
162-transaction chain corpus: it is a superset of the tags the probe rendered
for all 162.

### 3. `true` and the empty text string both render `t`

An ambiguity in the agreed grammar, not in either decoder. It can only cause a
false *negative* (a decoder that confused the two would still compare equal).
Closed directly by
`the_grammar_ambiguity_between_true_and_empty_text_is_not_a_decoder_bug`.

## Generators

| generator | inputs | what it produces |
|-----------|--------|------------------|
| `corner-sweep` | 66,908 | deterministic: every initial byte alone and padded, all 65,536 half floats, all 256 one-byte simple values, every head width × argument per major type, indefinite/break/bignum/depth corner cases |
| `random-bytes` | 60,000 | uniform random bytes, length 1..64 |
| `structured` | 60,000 | recursively generated valid CBOR, all major types, all head widths (including non-minimal), definite and indefinite, depth ≤ 6 |
| `structured-corrupted` | 40,000 | the above with 1–3 random byte mutations |
| `corpus-truncated` | 20,000 | random prefixes of the 162 real chain transactions plus the 8 Python-suite fixtures |
| `corpus-mutated` | 20,000 | single-byte replacements and single-bit flips of those transactions |

266,908 inputs, about 5 seconds wall time. 260,450 agreements; 178,591 of
those had their full structure compared, 6,517 their byte span only.

## Divergence classes found

The recorded run produced five, and no `rust-bug`:

| class | count | verdict | what it is |
|-------|-------|---------|------------|
| `semantic-tag-payload` | 5,657 | benign | `cbor2` runs a semantic decoder for the tag and rejects the payload (`d9010201` — tag 258 wrapping an int); the Rust decoder keeps `Value::Tag` and lets the validator reading the field reject it. Same rejection, different message. |
| `stray-break` | 441 | rust-stricter | A break byte with no open indefinite container. `cbor2` returns a `break_marker` object and will store it as an array item, a map value or even a map key (`ff`, `81ff`, `8201ff`, `a101ff`, `a1ff01`). RFC 8949 says none of that is well-formed. |
| `one-byte-simple-below-32` | 344 | rust-stricter | RFC 8949 §3.3 declares `f8 00`..`f8 1f` ill-formed: those simple values have a single-byte spelling. `cbor2` accepts them as `CBORSimpleValue`; the Rust decoder rejects them. No Cardano field is a major-7 simple value, and the divergence is in the rejecting direction. |
| `python-key-coercion` | 12 | benign | A Python `dict` collapses keys that compare equal across types, so for `a20102f503` (`{1: 2, true: 3}`) Python reads `body[1] == 3`. `Value::Map` keeps both entries, so the *renderings* differ; the *lookup* does not diverge, because `Value::map_get` refuses to read a map whose keys a Python dict would alias and the field reads as absent. Only reachable for a body map carrying a bool or float key, which the ledger's own body decoder rejects in phase 1. |
| `depth-cap` | 4 | rust-stricter | `MAX_DEPTH = 256` bounds recursion so a crafted payload cannot overflow the stack; `cbor2` only gives up around depth 500. |

`nan-payload` used to be a sixth class, 2,221 strong: `f16_to_f64` collapsed
every half-precision NaN to the canonical quiet NaN while `cbor2` preserved the
payload (`f97c01` → `7ff8000000000000` vs `7ff8040000000000`). The conversion
now reproduces `cbor2` bit for bit — pinned exhaustively over all 65,536 half
patterns by `every_half_float_pattern_matches_cbor2` — so the class is empty and
the classifier marks any reappearance `REVIEW`.

## Verdicts

Every divergence class carries one of:

* `rust-bug` — the Rust decoder is wrong. The fix phase must action it.
  `every_recorded_divergence_class_has_an_accepted_verdict` fails if one is
  committed.
* `rust-stricter` — Rust rejects what `cbor2` accepts, and rejecting is
  correct per RFC 8949.
* `benign` — a documented, harmless difference, with the reason recorded in
  the fixture's `why` field.

Anything the classifier cannot explain is emitted as `REVIEW`, which fails the
Rust suite. `--dump REVIEW` prints those cases for triage; classify them in
`classify()` once you understand them, or fix the decoder.

## Confirming the harness can fail

A fuzzer that reports nothing is worthless unless you have shown it can find
something. Two deliberate bugs were seeded into the probe — `consumed + 1` for
inputs over 40 bytes, and dropping the sign on negative integers — and the
quick run reported 1,697 `span-mismatch` and 1,096 `value-mismatch` cases, both
as `REVIEW`. Reverting the probe returned the run to zero unexplained
divergences. Repeat that if you ever change the comparison logic.
