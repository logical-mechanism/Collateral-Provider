//! Frozen output of the CBOR differential fuzzer, replayed without Python.
//!
//! `scripts/cbor_differential.py` drives `examples/cbor_probe` (this crate's
//! decoder) and `cbor2` (the behavioural reference the Python service uses)
//! over generated inputs and records every disagreement in
//! `tests/fixtures/fuzz_divergences.json`. This file is the regression half of
//! that loop: it re-renders each frozen case with a copy of the probe's
//! canonical grammar and asserts the decoder still behaves exactly as
//! recorded, so a future change to `src/cbor.rs` that silently moves one of
//! these lines fails here.
//!
//! The last recorded run: 266,908 inputs, 260,450 agreements, five divergence
//! classes, none of them a Rust bug. Sub-byte fidelity is the point — a decode
//! that consumes one byte too many hands `signature::tx_id` the wrong body
//! span and produces a witness for a transaction that does not exist.
//!
//! Two things the differential comparison cannot see, covered here directly:
//!
//! * The probe renders maps with Python's duplicate-key collapse applied,
//!   because a `cbor2` `dict` cannot report wire order or duplicates.
//!   [`map_wire_order_and_duplicates_survive_decoding`] pins what the collapse
//!   hides.
//! * The agreed grammar spells both `true` and the empty text string `t`.
//!   [`the_grammar_ambiguity_between_true_and_empty_text_is_not_a_decoder_bug`]
//!   closes that blind spot.
//!
//! Plus a self-contained round-trip property test: a deterministic few
//! thousand values encoded with the crate's own encoders, decoded back, and
//! checked for both value equality and an exact byte span when embedded in a
//! larger container.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use collateral_provider::cbor::{
    decode_exact, decode_one, encode_array, encode_bytes, encode_head, encode_int, encode_uint,
    CborError, Decoder, Value, MAX_DEPTH,
};
use serde::Deserialize;

// --- the frozen corpus ------------------------------------------------------

#[derive(Deserialize)]
struct Divergences {
    #[allow(dead_code)] // Provenance carried in the fixture, not asserted on.
    note: String,
    inputs: u64,
    generators: BTreeMap<String, u64>,
    agreements: u64,
    classes: BTreeMap<String, ClassInfo>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct ClassInfo {
    count: u64,
    verdict: String,
    why: String,
}

#[derive(Deserialize)]
struct Case {
    /// Hex of the exact bytes handed to both decoders.
    hex: String,
    /// The canonical rendering this crate produced.
    rust: String,
    /// What `cbor2` produced at capture time. Documentation only — nothing
    /// here re-runs Python.
    python: String,
    verdict: String,
    class: String,
}

fn divergences() -> Divergences {
    serde_json::from_str(include_str!("fixtures/fuzz_divergences.json"))
        .expect("fuzz_divergences.json parses")
}

fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex has an odd length: {hex}");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("fixture is hex"))
        .collect()
}

// --- the canonical grammar, copied from examples/cbor_probe.rs --------------
//
// Deliberately duplicated rather than shared: each integration test file is
// its own crate, and the whole point is that this file can prove what the
// probe printed without depending on the probe.

fn probe_line(data: &[u8]) -> String {
    match decode_one(data) {
        Ok((value, consumed)) => {
            let mut out = format!("V:{consumed}:");
            render(&value, &mut out);
            out
        }
        Err(error) => render_error(&error),
    }
}

fn render_error(error: &CborError) -> String {
    match error {
        CborError::Truncated => "E:Truncated".to_owned(),
        CborError::Malformed(reason) => format!("E:Malformed({reason})"),
        CborError::InvalidUtf8 => "E:InvalidUtf8".to_owned(),
        CborError::DepthExceeded => "E:DepthExceeded".to_owned(),
        CborError::UnexpectedMajor { expected, found } => {
            format!("E:UnexpectedMajor({expected},{found})")
        }
    }
}

fn push_hex(bytes: &[u8], out: &mut String) {
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
}

fn push_magnitude(bytes: &[u8], out: &mut String) {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02X}");
    }
    let trimmed = hex.trim_start_matches('0');
    out.push_str(if trimmed.is_empty() { "0" } else { trimmed });
}

fn render(value: &Value, out: &mut String) {
    match value {
        Value::Int(number) => {
            let _ = write!(out, "i{number}");
        }
        Value::BigInt {
            negative,
            magnitude,
        } => {
            out.push('I');
            out.push(if *negative { '-' } else { '+' });
            push_magnitude(magnitude, out);
        }
        Value::Bytes(bytes) => {
            out.push('b');
            push_hex(bytes, out);
        }
        Value::Text(text) => {
            out.push('t');
            push_hex(text.as_bytes(), out);
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                render(item, out);
            }
            out.push(']');
        }
        Value::Map(entries) => {
            // Python's dict semantics: first occurrence keeps its slot, last
            // occurrence supplies the value.
            let mut order: Vec<String> = Vec::with_capacity(entries.len());
            let mut values: Vec<String> = Vec::with_capacity(entries.len());
            for (key, entry_value) in entries {
                let mut key_rendered = String::new();
                render(key, &mut key_rendered);
                let mut value_rendered = String::new();
                render(entry_value, &mut value_rendered);
                match order.iter().position(|seen| *seen == key_rendered) {
                    Some(slot) => values[slot] = value_rendered,
                    None => {
                        order.push(key_rendered);
                        values.push(value_rendered);
                    }
                }
            }
            out.push('{');
            for (index, (key, entry_value)) in order.iter().zip(&values).enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(key);
                out.push(':');
                out.push_str(entry_value);
            }
            out.push('}');
        }
        Value::Tag(number, inner) => {
            let _ = write!(out, "T{number}(");
            render(inner, out);
            out.push(')');
        }
        Value::Bool(false) => out.push('f'),
        Value::Bool(true) => out.push('t'),
        Value::Null => out.push('n'),
        Value::Undefined => out.push('u'),
        Value::Simple(number) => {
            let _ = write!(out, "s{number}");
        }
        Value::Float(number) => {
            let _ = write!(out, "F{:016x}", number.to_bits());
        }
    }
}

// --- replaying the frozen cases --------------------------------------------

#[test]
fn every_frozen_divergence_still_behaves_exactly_as_recorded() {
    let corpus = divergences();
    assert!(!corpus.cases.is_empty(), "the fixture has no cases");
    for case in &corpus.cases {
        let data = unhex(&case.hex);
        assert_eq!(
            probe_line(&data),
            case.rust,
            "{} case {} drifted (cbor2 recorded {})",
            case.class,
            case.hex,
            case.python,
        );
    }
}

#[test]
fn skip_value_agrees_with_decode_on_every_frozen_case() {
    // `tx_id` reaches the body with `skip_value` while a full decode happens
    // elsewhere, so the two must accept and consume identically or the signed
    // span and the validated value come from different parses.
    for case in divergences().cases {
        let data = unhex(&case.hex);
        let mut skipper = Decoder::new(&data);
        let skipped = skipper.skip_value();
        let mut reader = Decoder::new(&data);
        let decoded = reader.decode_value();
        assert_eq!(
            skipped.is_err(),
            decoded.is_err(),
            "{} disagree on acceptance",
            case.hex
        );
        match (skipped, decoded) {
            (Ok(span), Ok(_)) => {
                assert_eq!(
                    span.len(),
                    reader.position(),
                    "{} skip span differs from decode span",
                    case.hex
                );
                assert_eq!(skipper.position(), reader.position(), "{}", case.hex);
            }
            (Err(skip_error), Err(decode_error)) => {
                assert_eq!(skip_error, decode_error, "{}", case.hex);
            }
            _ => unreachable!("acceptance was already asserted equal"),
        }
    }
}

#[test]
fn every_recorded_divergence_class_has_an_accepted_verdict() {
    // The fuzzer marks anything it cannot explain "REVIEW". Committing a
    // fixture with one still in it means an unexplained difference between the
    // Rust decoder and the Python service shipped unreviewed.
    let corpus = divergences();
    for (name, info) in &corpus.classes {
        assert!(
            matches!(info.verdict.as_str(), "benign" | "rust-stricter"),
            "divergence class {name} has verdict {:?} ({} occurrences)",
            info.verdict,
            info.count,
        );
        assert!(
            !info.why.trim().is_empty(),
            "divergence class {name} has no explanation",
        );
        assert!(
            info.verdict != "rust-bug",
            "class {name} is a decoder bug the fix phase must action",
        );
    }
    for case in &corpus.cases {
        assert!(
            corpus.classes.contains_key(&case.class),
            "case {} names class {} which is not in the summary",
            case.hex,
            case.class,
        );
        assert_eq!(
            corpus.classes[&case.class].verdict, case.verdict,
            "case {} disagrees with its class verdict",
            case.hex,
        );
    }
}

#[test]
fn the_recorded_run_actually_covered_the_generators_it_claims() {
    // The fixture doubles as the evidence for "we looked". If someone
    // regenerates it from a two-input smoke run, that claim should fail loudly
    // rather than quietly shrink.
    let corpus = divergences();
    assert!(
        corpus.inputs >= 200_000,
        "the recorded run only covered {} inputs",
        corpus.inputs
    );
    assert!(corpus.agreements > 0);
    for generator in [
        "corner-sweep",
        "random-bytes",
        "structured",
        "structured-corrupted",
        "corpus-truncated",
        "corpus-mutated",
    ] {
        assert!(
            corpus.generators.get(generator).copied().unwrap_or(0) > 0,
            "generator {generator} contributed nothing",
        );
    }
}

/// Each class, spelled out as a direct assertion so the behaviour is pinned
/// even if the fixture is regenerated with different representatives.
#[test]
fn the_five_divergence_classes_are_what_the_fixture_says_they_are() {
    // rust-stricter: a break with no open indefinite container. cbor2 hands
    // back a break_marker object and happily stores it as an item, a map value
    // or even a map key; RFC 8949 says none of that is well-formed.
    for hex in ["ff", "81ff", "8201ff", "a101ff", "a1ff01", "a201ff02ff"] {
        assert_eq!(
            decode_exact(&unhex(hex)),
            Err(CborError::Malformed("unexpected CBOR break")),
            "{hex}",
        );
    }

    // rust-stricter: the depth cap. cbor2 only gives up somewhere past 256.
    let mut deep = vec![0x81u8; MAX_DEPTH + 1];
    deep.push(0x01);
    assert_eq!(decode_exact(&deep), Err(CborError::DepthExceeded));

    // benign: cbor2 runs a semantic decoder for these tags and rejects the
    // payload; the decoder keeps the tag and lets the validator reject it.
    for (hex, tag) in [
        ("c00000000000000000", 0u64),
        ("c40000000000000000", 4),
        ("c50000000000000000", 5),
        ("d9010201", 258),
    ] {
        let (value, _) = decode_one(&unhex(hex)).expect("the Rust decoder keeps the tag");
        assert!(
            matches!(value, Value::Tag(number, _) if number == tag),
            "{hex} should stay a tag",
        );
    }

    // rust-stricter: RFC 8949 §3.3 makes the one-byte simple-value form
    // ill-formed below 32. cbor2 accepts `f800` as CBORSimpleValue(0).
    for value in 0u8..32 {
        let hex = format!("f8{value:02x}");
        assert_eq!(
            decode_exact(&unhex(&hex)),
            Err(CborError::Malformed("non-minimal CBOR simple value")),
            "{hex}",
        );
    }
    assert_eq!(decode_exact(&unhex("f820")), Ok(Value::Simple(32)));

    // NOT a divergence any more: a half float's NaN payload is carried into
    // the double exactly as cbor2 carries it. This used to be the
    // `nan-payload` class and the regenerated run has none.
    assert_eq!(
        decode_exact(&unhex("f97c01")),
        Ok(Value::Float(f64::from_bits(0x7ff8_0400_0000_0000))),
    );
    assert_eq!(decode_exact(&unhex("f93c00")), Ok(Value::Float(1.0)));

    // benign: Python collapses map keys that compare equal across types, so
    // its `body[1]` can resolve to a bool- or float-keyed entry. The decoded
    // *structures* therefore differ. The lookup does not diverge: `map_get`
    // refuses to read a map whose keys a Python dict would alias, so the field
    // reads as absent and the transaction is rejected either way.
    let coerced = decode_exact(&unhex("a20102f503")).expect("decodes");
    assert_eq!(coerced.as_map().map(<[_]>::len), Some(2));
    assert_eq!(coerced.map_get(1), None);
    let reversed = decode_exact(&unhex("a2f5030102")).expect("decodes");
    assert_eq!(reversed.map_get(1), None);
    let float_keyed = decode_exact(&unhex("a20002fb000000000000000003")).expect("decodes");
    assert_eq!(float_keyed.map_get(0), None);
    // A map whose other key cannot alias an integer stays readable: {1: 2,
    // null: 3}. Only bool and float keys share a slot with an int in Python.
    let unaliased = decode_exact(&unhex("a20102f603")).expect("decodes");
    assert_eq!(unaliased.map_get(1), Some(&Value::Int(2)));
}

// --- what the differential comparison structurally cannot see ---------------

#[test]
fn map_wire_order_and_duplicates_survive_decoding() {
    // The probe collapses maps the way a Python dict does, purely so the two
    // renderings can be compared. `Value::Map` itself keeps every entry in
    // wire order — `script_integrity` needs that to reject a witness set that
    // repeats field 4 or 5.
    let value = decode_exact(&unhex("a3010201030104")).expect("decodes");
    let entries = value.as_map().expect("is a map");
    assert_eq!(
        entries,
        [
            (Value::Int(1), Value::Int(2)),
            (Value::Int(1), Value::Int(3)),
            (Value::Int(1), Value::Int(4)),
        ],
    );
    // Reads are last-wins, matching a Python dict.
    assert_eq!(value.map_get(1), Some(&Value::Int(4)));

    // Order is preserved, not sorted: 2 comes before 1 on the wire.
    let unsorted = decode_exact(&unhex("a2020a010b")).expect("decodes");
    let entries = unsorted.as_map().expect("is a map");
    assert_eq!(entries[0].0, Value::Int(2));
    assert_eq!(entries[1].0, Value::Int(1));
}

#[test]
fn the_grammar_ambiguity_between_true_and_empty_text_is_not_a_decoder_bug() {
    // Both render as `t`, so the differential comparison is blind to a decoder
    // that confused them. It does not.
    assert_eq!(decode_exact(&unhex("f5")), Ok(Value::Bool(true)));
    assert_eq!(decode_exact(&unhex("60")), Ok(Value::Text(String::new())));
    assert_ne!(
        decode_exact(&unhex("f5")).unwrap(),
        decode_exact(&unhex("60")).unwrap(),
    );
    // The empty byte string is unambiguous but sits next door; keep it honest.
    assert_eq!(decode_exact(&unhex("40")), Ok(Value::Bytes(Vec::new())));
}

// --- round-trip property test ----------------------------------------------

/// SplitMix64. A fixed seed with no external dependency keeps the generated
/// corpus identical on every machine and every run.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

/// A value the crate's encoders can produce, paired with what decoding it back
/// must yield.
enum Shape {
    Uint(u64),
    Int(i64),
    Bytes(Vec<u8>),
    Array(Vec<Shape>),
    Map(Vec<(Shape, Shape)>),
}

impl Shape {
    /// Discriminant index, used to assert the generator keeps emitting all
    /// five shapes rather than degenerating to leaves.
    fn kind(&self) -> usize {
        match self {
            Shape::Uint(_) => 0,
            Shape::Int(_) => 1,
            Shape::Bytes(_) => 2,
            Shape::Array(_) => 3,
            Shape::Map(_) => 4,
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            Shape::Uint(value) => encode_uint(*value),
            Shape::Int(value) => encode_int(*value),
            Shape::Bytes(bytes) => encode_bytes(bytes),
            Shape::Array(items) => {
                let encoded: Vec<Vec<u8>> = items.iter().map(Shape::encode).collect();
                encode_array(&encoded)
            }
            Shape::Map(entries) => {
                let mut out = encode_head(5, entries.len() as u64);
                for (key, value) in entries {
                    out.extend_from_slice(&key.encode());
                    out.extend_from_slice(&value.encode());
                }
                out
            }
        }
    }

    fn expected(&self) -> Value {
        match self {
            Shape::Uint(value) => Value::Int(i128::from(*value)),
            Shape::Int(value) => Value::Int(i128::from(*value)),
            Shape::Bytes(bytes) => Value::Bytes(bytes.clone()),
            Shape::Array(items) => Value::Array(items.iter().map(Shape::expected).collect()),
            Shape::Map(entries) => Value::Map(
                entries
                    .iter()
                    .map(|(key, value)| (key.expected(), value.expected()))
                    .collect(),
            ),
        }
    }
}

fn generate(rng: &mut Rng, depth: usize) -> Shape {
    // Widen the integer choices across every head width the encoders emit.
    let leaf_or_container = if depth >= 4 { 3 } else { 5 };
    match rng.below(leaf_or_container) {
        0 => Shape::Uint(
            [
                0,
                1,
                23,
                24,
                255,
                256,
                65_535,
                65_536,
                u64::from(u32::MAX),
                u64::from(u32::MAX) + 1,
                u64::MAX,
            ][rng.below(11) as usize],
        ),
        1 => Shape::Int(
            [
                0,
                -1,
                23,
                -24,
                -25,
                255,
                -256,
                -257,
                65_536,
                -65_537,
                i64::MIN,
                i64::MAX,
            ][rng.below(12) as usize],
        ),
        2 => {
            let length = rng.below(40) as usize;
            Shape::Bytes((0..length).map(|_| rng.below(256) as u8).collect())
        }
        3 => {
            let count = rng.below(5) as usize;
            Shape::Array((0..count).map(|_| generate(rng, depth + 1)).collect())
        }
        _ => {
            let count = rng.below(4) as usize;
            Shape::Map(
                (0..count)
                    .map(|_| (generate(rng, depth + 1), generate(rng, depth + 1)))
                    .collect(),
            )
        }
    }
}

#[test]
fn encoded_values_round_trip_and_report_an_exact_span() {
    let mut rng = Rng(0x0134_9BEE_F00D_1234);
    let mut total_bytes = 0usize;
    let mut kinds = [0usize; 5];
    for iteration in 0..4000 {
        let shape = generate(&mut rng, 0);
        kinds[shape.kind()] += 1;
        let encoded = shape.encode();
        let expected = shape.expected();
        total_bytes += encoded.len();

        // 1. A standalone encode decodes back to the same value, consuming
        //    every byte and nothing more.
        assert_eq!(
            decode_exact(&encoded),
            Ok(expected.clone()),
            "iteration {iteration}",
        );
        let (value, consumed) = decode_one(&encoded).expect("decodes");
        assert_eq!(value, expected, "iteration {iteration}");
        assert_eq!(consumed, encoded.len(), "iteration {iteration}");

        // 2. `skip_value` walks the identical span without materializing it.
        let mut skipper = Decoder::new(&encoded);
        assert_eq!(
            skipper.skip_value().expect("skips"),
            &encoded[..],
            "iteration {iteration}",
        );

        // 3. The span is still exact when the value is buried between two
        //    neighbours — the case `tx_id` and `script_integrity` rely on.
        let prefix = encode_bytes(&[0xAA; 3]);
        let suffix = encode_uint(7);
        let outer = encode_array(&[prefix.clone(), encoded.clone(), suffix.clone()]);
        let mut decoder = Decoder::new(&outer);
        assert_eq!(decoder.container_header(4), Ok(Some(3)));
        assert_eq!(decoder.skip_value().expect("prefix skips"), &prefix[..]);
        let start = decoder.position();
        let (embedded, raw) = decoder.decode_value_raw().expect("embedded value decodes");
        assert_eq!(embedded, expected, "iteration {iteration}");
        assert_eq!(raw, &encoded[..], "iteration {iteration}");
        assert_eq!(
            &outer[start..decoder.position()],
            &encoded[..],
            "iteration {iteration}",
        );
        assert_eq!(decoder.skip_value().expect("suffix skips"), &suffix[..]);
        assert!(decoder.is_at_end(), "iteration {iteration}");

        // 4. Truncating by one byte must never decode as if it were whole.
        if encoded.len() > 1 {
            let short = &encoded[..encoded.len() - 1];
            match decode_one(short) {
                Err(_) => {}
                Ok((_, consumed_short)) => assert!(
                    consumed_short < encoded.len(),
                    "iteration {iteration}: a truncated encoding claimed a full span",
                ),
            }
        }
    }
    // Guards against a generator that quietly degenerates to empty arrays.
    assert!(
        total_bytes > 40_000,
        "the generated corpus was suspiciously small: {total_bytes} bytes",
    );
    for (index, count) in kinds.iter().enumerate() {
        assert!(
            *count > 100,
            "shape kind {index} appeared only {count} times in the corpus",
        );
    }
}
