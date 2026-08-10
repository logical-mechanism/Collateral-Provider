//! Codec-surface tests driven by 162 real transactions plus the 8 fixtures
//! lifted from the Python test suite.
//!
//! `differential.rs` already asks the narrow question the signing path cares
//! about — does `blake2b256(body span)` reproduce the id the chain assigned.
//! This file asks the wider one: is the *codec itself* self-consistent on real
//! wire bytes? Four independent readings of every transaction have to agree —
//! `decode_value_raw`, `skip_value`, a standalone re-decode of the extracted
//! slice, and a hand-rolled byte walker written from RFC 8949 that shares no
//! code with `cbor.rs`. A cursor that mis-measures one nested value will drift
//! between at least two of the four.
//!
//! The second half is corpus self-defence. Assertions like "tag-258 sets are
//! covered" are worthless if the corpus quietly stops containing any, so each
//! structural shape the port claims to handle has a test that fails when its
//! count reaches zero. `corpus_shape_summary` prints the whole distribution
//! (`cargo test --test cbor_chain_corpus -- --nocapture corpus_shape_summary`).
//!
//! Everything here is frozen: no network, no Python, no clock. Expected values
//! that came from `cbor2` were measured once in this repo's venv and written in
//! as literals.

use std::collections::BTreeMap;

use collateral_provider::cbor::{self, CborError, Decoder, Value};
use collateral_provider::signature;
use collateral_provider::validators::cbor as cbor_validators;
use serde::Deserialize;

// --- fixtures ---------------------------------------------------------------

#[derive(Deserialize)]
struct Corpus<T> {
    #[allow(dead_code)] // Provenance note carried in the fixture, not asserted on.
    note: String,
    transactions: Vec<T>,
}

#[derive(Deserialize)]
struct ChainCase {
    network: String,
    epoch: u64,
    #[allow(dead_code)] // Recorded for provenance when a case needs re-fetching.
    block_height: u64,
    tx_hash: String,
    body_span: (usize, usize),
    cbor: String,
}

#[derive(Deserialize)]
struct PythonCase {
    name: String,
    #[allow(dead_code)] // Which Python fixture module the case came from.
    source: String,
    cbor: String,
    body_span: (usize, usize),
    tx_id: String,
}

fn chain_corpus() -> Vec<ChainCase> {
    let raw = include_str!("fixtures/chain_corpus.json");
    serde_json::from_str::<Corpus<ChainCase>>(raw)
        .expect("chain_corpus.json parses")
        .transactions
}

fn python_suite() -> Vec<PythonCase> {
    let raw = include_str!("fixtures/python_suite.json");
    serde_json::from_str::<Corpus<PythonCase>>(raw)
        .expect("python_suite.json parses")
        .transactions
}

impl ChainCase {
    fn bytes(&self) -> Vec<u8> {
        hex::decode(&self.cbor).expect("fixture cbor is hex")
    }

    fn label(&self) -> String {
        format!("{} epoch {} {}", self.network, self.epoch, self.tx_hash)
    }
}

// --- an independent byte walker ---------------------------------------------
//
// Written straight from RFC 8949's head encoding and deliberately sharing
// nothing with `cbor.rs`. Its only job is to answer "where does this value
// end?" a second time, so a span bug in the real decoder has somewhere to
// show up. It does not validate UTF-8 and has no depth limit — the corpus is
// known-good wire data, and acceptance policy is the real decoder's business.

#[derive(Default, Clone)]
struct RawStats {
    nodes: usize,
    max_depth: usize,
    indefinite_array: usize,
    indefinite_map: usize,
    indefinite_bytes: usize,
    indefinite_text: usize,
    negative_ints: usize,
    tags: BTreeMap<u64, usize>,
    /// Major-7 heads by additional-information value: 20 false, 21 true,
    /// 22 null, 23 undefined, 24 one-byte simple, 25/26/27 floats.
    major7: BTreeMap<u8, usize>,
}

impl RawStats {
    fn indefinite_total(&self) -> usize {
        self.indefinite_array + self.indefinite_map + self.indefinite_bytes + self.indefinite_text
    }

    fn merge(&mut self, other: &RawStats) {
        self.nodes += other.nodes;
        self.max_depth = self.max_depth.max(other.max_depth);
        self.indefinite_array += other.indefinite_array;
        self.indefinite_map += other.indefinite_map;
        self.indefinite_bytes += other.indefinite_bytes;
        self.indefinite_text += other.indefinite_text;
        self.negative_ints += other.negative_ints;
        for (tag, count) in &other.tags {
            *self.tags.entry(*tag).or_default() += count;
        }
        for (info, count) in &other.major7 {
            *self.major7.entry(*info).or_default() += count;
        }
    }
}

struct RawWalker<'a> {
    data: &'a [u8],
    pos: usize,
    stats: RawStats,
}

impl<'a> RawWalker<'a> {
    fn new(data: &'a [u8]) -> Self {
        RawWalker {
            data,
            pos: 0,
            stats: RawStats::default(),
        }
    }

    fn byte(&mut self) -> Result<u8, String> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or_else(|| format!("truncated at offset {}", self.pos))?;
        self.pos += 1;
        Ok(byte)
    }

    fn uint(&mut self, width: usize) -> Result<u64, String> {
        let mut value = 0u64;
        for _ in 0..width {
            value = (value << 8) | u64::from(self.byte()?);
        }
        Ok(value)
    }

    /// `(major, additional info, argument)`; the argument is `None` for the
    /// indefinite form. The raw info comes back too because major 7 needs the
    /// head *width* to tell false from null from a half float.
    fn head(&mut self) -> Result<(u8, u8, Option<u64>), String> {
        let start = self.pos;
        let initial = self.byte()?;
        let (major, info) = (initial >> 5, initial & 0x1F);
        let argument = match info {
            0..=23 => Some(u64::from(info)),
            24 => Some(self.uint(1)?),
            25 => Some(self.uint(2)?),
            26 => Some(self.uint(4)?),
            27 => Some(self.uint(8)?),
            31 => None,
            _ => return Err(format!("reserved additional info {info} at offset {start}")),
        };
        Ok((major, info, argument))
    }

    fn take(&mut self, len: u64) -> Result<(), String> {
        let len = usize::try_from(len).map_err(|_| "payload length exceeds usize".to_string())?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| "payload length overflows".to_string())?;
        if end > self.data.len() {
            return Err(format!("payload runs past the end at offset {}", self.pos));
        }
        self.pos = end;
        Ok(())
    }

    fn at_break(&self) -> bool {
        self.data.get(self.pos) == Some(&0xFF)
    }

    fn chunks(&mut self, major: u8) -> Result<(), String> {
        loop {
            if self.at_break() {
                self.pos += 1;
                return Ok(());
            }
            self.stats.nodes += 1;
            let (chunk_major, _, argument) = self.head()?;
            if chunk_major != major {
                return Err(format!("chunk major {chunk_major} inside major {major}"));
            }
            let Some(len) = argument else {
                return Err("nested indefinite string chunk".to_string());
            };
            self.take(len)?;
        }
    }

    fn value(&mut self, depth: usize) -> Result<(), String> {
        self.stats.nodes += 1;
        self.stats.max_depth = self.stats.max_depth.max(depth);
        let (major, info, argument) = self.head()?;
        match (major, argument) {
            (0, Some(_)) => Ok(()),
            (1, Some(_)) => {
                self.stats.negative_ints += 1;
                Ok(())
            }
            (2, Some(len)) | (3, Some(len)) => self.take(len),
            (2, None) => {
                self.stats.indefinite_bytes += 1;
                self.chunks(2)
            }
            (3, None) => {
                self.stats.indefinite_text += 1;
                self.chunks(3)
            }
            (4, Some(len)) => {
                for _ in 0..len {
                    self.value(depth + 1)?;
                }
                Ok(())
            }
            (4, None) => {
                self.stats.indefinite_array += 1;
                while !self.at_break() {
                    self.value(depth + 1)?;
                }
                self.pos += 1;
                Ok(())
            }
            (5, Some(len)) => {
                for _ in 0..len {
                    self.value(depth + 1)?;
                    self.value(depth + 1)?;
                }
                Ok(())
            }
            (5, None) => {
                self.stats.indefinite_map += 1;
                while !self.at_break() {
                    self.value(depth + 1)?;
                    self.value(depth + 1)?;
                }
                self.pos += 1;
                Ok(())
            }
            (6, Some(tag)) => {
                *self.stats.tags.entry(tag).or_default() += 1;
                self.value(depth + 1)
            }
            (7, Some(_)) => {
                *self.stats.major7.entry(info).or_default() += 1;
                Ok(())
            }
            _ => Err(format!("indefinite length is invalid for major {major}")),
        }
    }
}

/// Walk a whole transaction independently and report `(body span, stats)`.
fn walk_transaction(bytes: &[u8]) -> Result<((usize, usize), RawStats), String> {
    let mut walker = RawWalker::new(bytes);
    walker.stats.nodes += 1; // the envelope array itself
    let (major, _, _) = walker.head()?;
    if major != 4 {
        return Err(format!("envelope major is {major}, not an array"));
    }
    let start = walker.pos;
    walker.value(1)?;
    let end = walker.pos;
    // Finish the rest of the envelope so the stats cover the whole input and
    // the "consumes everything" check is meaningful.
    while !walker.at_break() && walker.pos < bytes.len() {
        walker.value(1)?;
    }
    if walker.at_break() {
        walker.pos += 1;
    }
    if walker.pos != bytes.len() {
        return Err(format!(
            "walker stopped at {} of {} bytes",
            walker.pos,
            bytes.len()
        ));
    }
    Ok(((start, end), walker.stats))
}

// --- helpers shared by the tests --------------------------------------------

/// The body span as the signing path measures it: array header, then one value.
fn decoder_body_span(bytes: &[u8]) -> Result<(usize, usize), CborError> {
    let mut decoder = Decoder::new(bytes);
    decoder.skip_array_header()?;
    let start = decoder.position();
    decoder.skip_value()?;
    Ok((start, decoder.position()))
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Int(_) => "int",
        Value::BigInt { .. } => "bignum",
        Value::Bytes(_) => "bytes",
        Value::Text(_) => "text",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tag",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        Value::Undefined => "undefined",
        Value::Simple(_) => "simple",
        Value::Float(_) => "float",
    }
}

/// Integers that would not survive a `u64` conversion, split by why. The
/// report needs to state honestly which of these the corpus actually
/// exercises: negatives yes (burn quantities), bignums no.
#[derive(Default)]
struct IntSpread {
    bignums: usize,
    above_u64: usize,
    negatives: usize,
}

fn count_out_of_u64_range(value: &Value, spread: &mut IntSpread) {
    match value {
        Value::BigInt { .. } => spread.bignums += 1,
        Value::Int(int) => {
            if *int < 0 {
                spread.negatives += 1;
            } else if u64::try_from(*int).is_err() {
                spread.above_u64 += 1;
            }
        }
        Value::Array(items) => {
            for item in items {
                count_out_of_u64_range(item, spread);
            }
        }
        Value::Map(entries) => {
            for (key, entry) in entries {
                count_out_of_u64_range(key, spread);
                count_out_of_u64_range(entry, spread);
            }
        }
        Value::Tag(_, inner) => count_out_of_u64_range(inner, spread),
        _ => {}
    }
}

// === 1. every transaction decodes, exactly ==================================

/// `decode_one` must consume the input to the last byte and nothing beyond it,
/// and the envelope must be the shape the rest of the service assumes.
#[test]
fn every_transaction_decodes_and_consumes_the_whole_input() {
    let cases = chain_corpus();
    assert!(
        cases.len() >= 150,
        "corpus shrank unexpectedly: {} entries",
        cases.len()
    );

    for case in &cases {
        let bytes = case.bytes();
        let label = case.label();

        let (value, consumed) =
            cbor::decode_one(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(
            consumed,
            bytes.len(),
            "{label}: decode_one left {} trailing bytes",
            bytes.len() - consumed
        );

        // The convenience wrapper must agree with the cursor form.
        let exact = cbor::decode_exact(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(exact, value, "{label}: decode_exact != decode_one");

        let items = value
            .as_array()
            .unwrap_or_else(|| panic!("{label}: envelope is {}", value_kind(&value)));
        assert!(
            items.len() == 3 || items.len() == 4,
            "{label}: envelope arity {}",
            items.len()
        );
        assert!(
            items[0].as_map().is_some(),
            "{label}: body is {}, not a map",
            value_kind(&items[0])
        );
        // Every era in the corpus encodes the witness set as a map; a list
        // here would mean the witness-set cursors are reading the wrong shape.
        assert!(
            items[1].as_map().is_some(),
            "{label}: witness set is {}, not a map",
            value_kind(&items[1])
        );
    }
}

/// Appending a single byte must be rejected rather than silently ignored —
/// `decode_exact` is what stops a caller smuggling bytes past the validators.
#[test]
fn a_trailing_byte_is_rejected_on_real_transactions() {
    for case in chain_corpus().iter().take(20) {
        let mut bytes = case.bytes();
        bytes.push(0x00);
        assert_eq!(
            cbor::decode_exact(&bytes),
            Err(CborError::Malformed("trailing CBOR data")),
            "{}: trailing byte accepted",
            case.label()
        );
    }
}

// === 2/3. the body span, measured four ways =================================

/// The span the signing path takes must equal the recorded offsets, the slice
/// must be a verbatim window into the input, and its digest must be the id the
/// chain itself assigned. `signature::tx_id` walks one path; the raw cursor
/// walks the other; they have to land on the same 32 bytes.
#[test]
fn body_span_is_verbatim_and_hashes_to_the_chain_id() {
    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();

        let mut decoder = Decoder::new(&bytes);
        decoder
            .skip_array_header()
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        let start = decoder.position();
        let (body, raw) = decoder
            .decode_value_raw()
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        let end = decoder.position();

        assert_eq!(
            (start, end),
            case.body_span,
            "{label}: decode_value_raw span disagrees with the fixture"
        );
        // `raw` must be the input's own bytes, not a re-encoding that happens
        // to be the same length.
        assert_eq!(
            raw,
            &bytes[start..end],
            "{label}: raw slice is not a window"
        );
        assert!(
            body.as_map().is_some(),
            "{label}: body decoded as {}",
            value_kind(&body)
        );

        // Path A: hash the cursor's slice directly.
        let from_cursor = hex::encode(signature::blake2b(raw, 32));
        // Path B: the production entry point, which re-derives the span itself.
        let from_signature =
            signature::tx_id(&case.cbor).unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(
            from_cursor, case.tx_hash,
            "{label}: cursor slice does not hash to the chain id"
        );
        assert_eq!(
            from_signature, from_cursor,
            "{label}: signature::tx_id and the raw cursor disagree"
        );
    }
}

/// `skip_value` is the faster path used by `tx_id`; it must consume byte for
/// byte what `decode_value_raw` consumes, or the two callers of the codec will
/// hash different things.
#[test]
fn skip_value_consumes_exactly_what_decode_value_raw_consumes() {
    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();

        let mut skipper = Decoder::new(&bytes);
        skipper
            .skip_array_header()
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        let skipped = skipper
            .skip_value()
            .unwrap_or_else(|err| panic!("{label}: {err}"));

        let span = decoder_body_span(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(span, case.body_span, "{label}: skip_value span drifted");
        assert_eq!(
            skipped,
            &bytes[case.body_span.0..case.body_span.1],
            "{label}: skip_value returned the wrong slice"
        );

        // Skipping the remaining envelope elements must land exactly on the
        // end of the input — this is what proves the cursor arithmetic holds
        // for the witness set and auxiliary data too, not just the body.
        while !skipper.is_at_end() && !skipper.at_break() {
            skipper
                .skip_value()
                .unwrap_or_else(|err| panic!("{label}: skipping envelope tail: {err}"));
        }
        if skipper.at_break() {
            skipper
                .consume_break()
                .unwrap_or_else(|err| panic!("{label}: {err}"));
        }
        assert_eq!(
            skipper.position(),
            bytes.len(),
            "{label}: envelope element spans do not tile the input"
        );
        assert!(skipper.remaining().is_empty(), "{label}: bytes left over");
    }
}

/// A fourth reading, from a walker that shares no code with `cbor.rs`. If the
/// real decoder mis-measures a nested value, the two spans part company here
/// even when the fixture and the hash happen to agree.
#[test]
fn an_independent_walker_measures_the_same_body_span() {
    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();
        let (span, _stats) =
            walk_transaction(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(
            span, case.body_span,
            "{label}: the independent walker disagrees about the body span"
        );
    }
}

// === 4/5. the span is self-contained ========================================

/// Sliced out on its own, the body must decode to exactly the same map with no
/// leftovers. A span that is one byte long or short would either fail to
/// decode or leave a trailing byte here.
#[test]
fn the_body_slice_decodes_standalone_to_the_same_map() {
    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();
        let (start, end) = case.body_span;

        let mut decoder = Decoder::new(&bytes);
        decoder.set_position(start);
        let in_place = decoder
            .decode_value()
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(decoder.position(), end, "{label}: set_position round trip");

        let standalone = cbor::decode_exact(&bytes[start..end])
            .unwrap_or_else(|err| panic!("{label}: body slice does not stand alone: {err}"));
        assert_eq!(
            standalone, in_place,
            "{label}: the isolated body decodes differently"
        );

        // And the digest of the isolated slice is still the chain's id.
        assert_eq!(
            hex::encode(signature::blake2b(&bytes[start..end], 32)),
            case.tx_hash,
            "{label}: isolated slice hashes differently"
        );
    }
}

/// Every nested value in every transaction, not just the body: the bytes
/// `decode_value_raw` hands back must re-decode to the identical value, and
/// `skip_value` must consume the same range. This is the property
/// `script_integrity` depends on when it slices witness-set fields 4 and 5.
#[test]
fn every_nested_value_is_a_self_contained_slice() {
    /// Count the nodes of an already-decoded tree, so the cursor walk below
    /// can be checked for having visited every one of them.
    fn count_nodes(value: &Value, counted: &mut usize) {
        match value {
            Value::Array(items) => {
                for item in items {
                    count_nodes(item, counted);
                }
            }
            Value::Map(entries) => {
                for (key, entry) in entries {
                    count_nodes(key, counted);
                    count_nodes(entry, counted);
                }
            }
            Value::Tag(_, inner) => count_nodes(inner, counted),
            _ => {}
        }
        *counted += 1;
    }

    /// Width of a CBOR head, from its initial byte. Used only to step over a
    /// tag head; the decoder has no public accessor for that.
    fn head_len(initial: u8) -> usize {
        match initial & 0x1F {
            0..=23 => 1,
            24 => 2,
            25 => 3,
            26 => 5,
            _ => 9,
        }
    }

    // Walk the raw bytes with the real decoder, verifying slice-identity at
    // every offset the cursor visits.
    fn walk(decoder_data: &[u8], pos: usize, label: &str, checked: &mut usize) -> usize {
        let mut raw_cursor = Decoder::new(decoder_data);
        raw_cursor.set_position(pos);
        let (value, raw) = raw_cursor
            .decode_value_raw()
            .unwrap_or_else(|err| panic!("{label}: at offset {pos}: {err}"));
        let end = raw_cursor.position();

        let mut skip_cursor = Decoder::new(decoder_data);
        skip_cursor.set_position(pos);
        let skipped = skip_cursor
            .skip_value()
            .unwrap_or_else(|err| panic!("{label}: skip at offset {pos}: {err}"));
        assert_eq!(
            skip_cursor.position(),
            end,
            "{label}: skip_value and decode_value_raw disagree at offset {pos}"
        );
        assert_eq!(skipped, raw, "{label}: slices differ at offset {pos}");

        let reparsed = cbor::decode_exact(raw)
            .unwrap_or_else(|err| panic!("{label}: slice at {pos} does not stand alone: {err}"));
        assert_eq!(
            reparsed, value,
            "{label}: slice at {pos} re-decodes differently"
        );
        *checked += 1;

        // Recurse into the children by cursor position, not by index, so the
        // child offsets themselves are exercised.
        let mut child = Decoder::new(decoder_data);
        child.set_position(pos);
        match &value {
            Value::Array(_) | Value::Map(_) => {
                let major = if matches!(value, Value::Array(_)) {
                    4
                } else {
                    5
                };
                let len = child
                    .container_header(major)
                    .unwrap_or_else(|err| panic!("{label}: header at {pos}: {err}"));
                let per_entry = if major == 5 { 2 } else { 1 };
                match len {
                    Some(count) => {
                        for _ in 0..count * per_entry {
                            let next = child.position();
                            let consumed = walk(decoder_data, next, label, checked);
                            child.set_position(consumed);
                        }
                    }
                    None => {
                        while !child.at_break() {
                            for _ in 0..per_entry {
                                let next = child.position();
                                let consumed = walk(decoder_data, next, label, checked);
                                child.set_position(consumed);
                            }
                        }
                        child
                            .consume_break()
                            .unwrap_or_else(|err| panic!("{label}: {err}"));
                    }
                }
                assert_eq!(
                    child.position(),
                    end,
                    "{label}: container children do not tile the container at {pos}"
                );
            }
            Value::Tag(_, _) => {
                // Bignum tags decode to `Value::Int`, so reaching this arm
                // means the head really is a tag that stayed a tag.
                let inner = pos + head_len(decoder_data[pos]);
                let consumed = walk(decoder_data, inner, label, checked);
                assert_eq!(
                    consumed, end,
                    "{label}: tag payload does not fill the tag at {pos}"
                );
            }
            _ => {}
        }
        end
    }

    let mut visited = 0usize;
    let mut tree_nodes = 0usize;
    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();
        let end = walk(&bytes, 0, &label, &mut visited);
        assert_eq!(end, bytes.len(), "{label}: walk stopped early");

        let value = cbor::decode_exact(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        count_nodes(&value, &mut tree_nodes);
    }
    // Both walks count a tag as one node and an indefinite string as one
    // value, so the totals must line up exactly (15516 for this corpus; the
    // wire has 15526 heads, the extra ten being indefinite-string chunks).
    assert_eq!(
        visited, tree_nodes,
        "cursor walk and tree walk visited different node counts"
    );
    assert!(
        visited >= 10_000,
        "only {visited} nested values exercised; the corpus lost depth"
    );
}

// === 6. map_get semantics ===================================================

/// Every body field must be reachable through `map_get`, which is the only
/// accessor the validators use. Keys are integers in all 162 transactions; a
/// text or bytes key would mean a body shape nothing downstream can read.
#[test]
fn every_body_field_round_trips_through_map_get() {
    let mut fields_seen = 0usize;
    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();
        let envelope = cbor::decode_exact(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        let body = &envelope.as_array().expect("array envelope")[0];
        let entries = body.as_map().expect("map body");

        for (index, (key, _)) in entries.iter().enumerate() {
            let key_int = key
                .as_int()
                .unwrap_or_else(|| panic!("{label}: body key {index} is {}", value_kind(key)));
            let got = body
                .map_get(key_int)
                .unwrap_or_else(|| panic!("{label}: map_get({key_int}) missed a present field"));
            assert!(
                body.map_contains(key_int),
                "{label}: map_contains({key_int}) disagrees with map_get"
            );

            // Last-wins: the reference must be the *final* entry with this key.
            let last = entries
                .iter()
                .rposition(|(entry_key, _)| entry_key.as_int() == Some(key_int))
                .expect("the key we just read");
            assert!(
                std::ptr::eq(got, &entries[last].1),
                "{label}: map_get({key_int}) did not return the last entry"
            );
            fields_seen += 1;
        }

        // Keys nothing uses must miss cleanly rather than wrap or panic.
        for absent in [i128::MIN, i128::MAX, -1, 9_999] {
            assert!(
                body.map_get(absent).is_none(),
                "{label}: map_get({absent}) invented a field"
            );
        }
    }
    // 1093 integer-keyed fields across the corpus, measured with cbor2.
    assert!(
        fields_seen >= 1_000,
        "only {fields_seen} body fields exercised"
    );
}

/// No real transaction repeats a body key, so last-wins is pinned with a
/// hand-built map. `cbor2.loads(bytes.fromhex("a3000101020003"))` was measured
/// in this repo's venv and returns `{0: 3, 1: 2}` — the second `0` wins.
#[test]
fn map_get_returns_the_last_entry_for_a_repeated_key() {
    // map(3) { 0: 1, 1: 2, 0: 3 }
    let bytes = hex::decode("a3000101020003").expect("hex");
    let value = cbor::decode_exact(&bytes).expect("duplicate keys decode");

    // Unlike a Python dict, the decoded map keeps both entries in wire order.
    assert_eq!(
        value.as_map().expect("map").len(),
        3,
        "duplicates must be preserved on the wire side"
    );
    // ... but the accessor collapses them the way cbor2's dict does.
    assert_eq!(
        value.map_get(0),
        Some(&Value::Int(3)),
        "0 must be last-wins"
    );
    assert_eq!(value.map_get(1), Some(&Value::Int(2)));
    assert!(value.map_contains(0) && value.map_contains(1));
    assert!(value.map_get(2).is_none());
}

// === 7. envelope tail shapes ================================================

/// Element 2 of a four-element envelope is the `is_valid` flag and element 3 is
/// auxiliary data. Both are read by validators, so their decoded types matter.
#[test]
fn envelope_tail_has_the_expected_shapes() {
    let mut four = 0usize;
    let mut three = 0usize;
    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();
        let envelope = cbor::decode_exact(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        let items = envelope.as_array().expect("array envelope");

        if items.len() == 4 {
            four += 1;
            assert!(
                items[2].as_bool().is_some(),
                "{label}: is_valid is {}, not a bool",
                value_kind(&items[2])
            );
            assert!(
                matches!(
                    items[3],
                    Value::Null | Value::Map(_) | Value::Array(_) | Value::Tag(_, _)
                ),
                "{label}: auxiliary data is {}",
                value_kind(&items[3])
            );
        } else {
            three += 1;
            // Pre-Alonzo: no is_valid flag, element 2 is the auxiliary data.
            assert!(
                matches!(
                    items[2],
                    Value::Null | Value::Map(_) | Value::Array(_) | Value::Tag(_, _)
                ),
                "{label}: three-element tail is {}",
                value_kind(&items[2])
            );
            assert!(
                items[2].as_bool().is_none(),
                "{label}: three-element envelope carries a bool where aux data belongs"
            );
        }
    }
    assert!(four >= 100, "only {four} four-element envelopes");
    assert!(three >= 10, "only {three} pre-Alonzo envelopes");
}

// === container_header on real headers =======================================

/// `container_header` is the typed entry point the witness-set cursors use. On
/// real transactions it must report the true arity and leave the cursor on the
/// first item, and it must refuse the wrong major type without moving on.
#[test]
fn container_header_reports_real_arities() {
    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();

        let mut decoder = Decoder::new(&bytes);
        let arity = decoder
            .container_header(4)
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        let envelope = cbor::decode_exact(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        let items = envelope.as_array().expect("array envelope");
        match arity {
            Some(count) => assert_eq!(
                usize::try_from(count).unwrap(),
                items.len(),
                "{label}: envelope arity mismatch"
            ),
            None => panic!("{label}: no corpus transaction uses an indefinite envelope"),
        }

        // The body header, read from the position the envelope header left.
        let body_entries = decoder
            .container_header(5)
            .unwrap_or_else(|err| panic!("{label}: body header: {err}"));
        assert_eq!(
            body_entries.map(|count| usize::try_from(count).unwrap()),
            Some(items[0].as_map().expect("map body").len()),
            "{label}: body map arity mismatch"
        );

        // Asking for the wrong major must be an explicit type error.
        let mut wrong = Decoder::new(&bytes);
        assert_eq!(
            wrong.container_header(5),
            Err(CborError::UnexpectedMajor {
                expected: 5,
                found: 4
            }),
            "{label}: envelope accepted as a map"
        );
    }
}

// === the shapes the validators actually index into ==========================

/// `index_or_key` is what lets one output check serve both Shelley list-encoded
/// and Babbage map-encoded outputs. Slot 0 is the address in both, and it must
/// come back as bytes for every output in the corpus — that is the value
/// `check_outputs` hex-encodes and compares against the ban list.
#[test]
fn output_address_slot_reads_the_same_for_both_encodings() {
    let mut arrays = 0usize;
    let mut maps = 0usize;
    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();
        let envelope = cbor::decode_exact(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        let body = &envelope.as_array().expect("array envelope")[0];
        let outputs = body
            .map_get(1)
            .and_then(|value| value.as_array())
            .unwrap_or_else(|| panic!("{label}: outputs are missing or not a list"));

        for (index, output) in outputs.iter().enumerate() {
            match output {
                Value::Array(_) => arrays += 1,
                Value::Map(_) => maps += 1,
                other => panic!("{label}: output {index} is {}", value_kind(other)),
            }
            let address = output
                .index_or_key(0)
                .unwrap_or_else(|| panic!("{label}: output {index} has no slot 0"));
            assert!(
                address.as_bytes().is_some(),
                "{label}: output {index} address is {}",
                value_kind(address)
            );
        }
    }
    assert!(arrays > 0 && maps > 0, "one output encoding vanished");
}

/// `set_items` must normalize the inputs field under either Conway encoding,
/// and every entry must be the `[32-byte tx id, index]` pair `check_inputs`
/// compares against the configured collateral UTxO.
#[test]
fn input_sets_normalize_under_both_conway_encodings() {
    let mut entries_seen = 0usize;
    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();
        let envelope = cbor::decode_exact(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        let body = &envelope.as_array().expect("array envelope")[0];
        let inputs = body
            .map_get(0)
            .unwrap_or_else(|| panic!("{label}: no inputs field"));

        let items = cbor_validators::set_items(inputs)
            .unwrap_or_else(|| panic!("{label}: inputs are {}", value_kind(inputs)));
        assert!(!items.is_empty(), "{label}: empty input set");
        for entry in items {
            let pair = entry
                .as_array()
                .unwrap_or_else(|| panic!("{label}: input entry is {}", value_kind(entry)));
            assert_eq!(pair.len(), 2, "{label}: input entry is not a pair");
            assert_eq!(
                pair[0].as_bytes().map(<[u8]>::len),
                Some(32),
                "{label}: input tx id is not 32 bytes"
            );
            assert!(
                pair[1].as_u64().is_some(),
                "{label}: input index is {}",
                value_kind(&pair[1])
            );
            entries_seen += 1;
        }
    }
    // 383 inputs across the corpus, counted with cbor2.
    assert!(entries_seen >= 350, "only {entries_seen} inputs exercised");
}

// === corpus coverage ========================================================

#[derive(Default)]
struct Coverage {
    total: usize,
    arity3: usize,
    arity4: usize,
    tagged_input_sets: usize,
    untagged_input_sets: usize,
    txs_with_array_output: usize,
    txs_with_map_output: usize,
    map_redeemers: usize,
    list_redeemers: usize,
    no_redeemers: usize,
    body_fields: BTreeMap<i128, usize>,
    aux_kinds: BTreeMap<&'static str, usize>,
    indefinite_txs: usize,
    definite_only_txs: usize,
    ints: IntSpread,
    txs_with_negative_ints: usize,
    networks: BTreeMap<String, usize>,
    raw: RawStats,
    min_epoch: u64,
    max_epoch: u64,
    total_bytes: usize,
}

fn measure_corpus() -> Coverage {
    let mut coverage = Coverage {
        min_epoch: u64::MAX,
        ..Coverage::default()
    };

    for case in &chain_corpus() {
        let bytes = case.bytes();
        let label = case.label();
        coverage.total += 1;
        coverage.total_bytes += bytes.len();
        coverage.min_epoch = coverage.min_epoch.min(case.epoch);
        coverage.max_epoch = coverage.max_epoch.max(case.epoch);
        *coverage.networks.entry(case.network.clone()).or_default() += 1;

        let (_, stats) = walk_transaction(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        if stats.indefinite_total() > 0 {
            coverage.indefinite_txs += 1;
        } else {
            coverage.definite_only_txs += 1;
        }
        coverage.raw.merge(&stats);

        let envelope = cbor::decode_exact(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        let before = coverage.ints.negatives;
        count_out_of_u64_range(&envelope, &mut coverage.ints);
        if coverage.ints.negatives > before {
            coverage.txs_with_negative_ints += 1;
        }
        let items = envelope.as_array().expect("array envelope");
        if items.len() == 4 {
            coverage.arity4 += 1;
            *coverage.aux_kinds.entry(value_kind(&items[3])).or_default() += 1;
        } else {
            coverage.arity3 += 1;
        }

        let body = &items[0];
        for (key, _) in body.as_map().expect("map body") {
            if let Some(field) = key.as_int() {
                *coverage.body_fields.entry(field).or_default() += 1;
            }
        }

        match body.map_get(0) {
            Some(Value::Tag(cbor::SET_TAG, _)) => coverage.tagged_input_sets += 1,
            Some(Value::Array(_)) => coverage.untagged_input_sets += 1,
            _ => {}
        }

        if let Some(outputs) = body.map_get(1).and_then(|value| value.as_array()) {
            if outputs.iter().any(|out| matches!(out, Value::Array(_))) {
                coverage.txs_with_array_output += 1;
            }
            if outputs.iter().any(|out| matches!(out, Value::Map(_))) {
                coverage.txs_with_map_output += 1;
            }
        }

        // Witness-set field 5: Alonzo encodes redeemers as a list of
        // four-element entries, Conway as a map keyed by [tag, index].
        match items[1].map_get(5) {
            Some(Value::Map(_)) => coverage.map_redeemers += 1,
            Some(Value::Array(_)) => coverage.list_redeemers += 1,
            _ => coverage.no_redeemers += 1,
        }
    }
    coverage
}

/// Both Conway `set` encodings must stay represented — gating on tag 258 alone
/// is the exact bug `set_items` exists to prevent.
#[test]
fn corpus_covers_both_input_set_encodings() {
    let coverage = measure_corpus();
    assert!(
        coverage.tagged_input_sets > 0,
        "no transaction encodes inputs with tag 258 any more"
    );
    assert!(
        coverage.untagged_input_sets > 0,
        "no transaction encodes inputs as a bare array any more"
    );
}

/// Shelley list-encoded and Babbage map-encoded outputs are read by the same
/// `index_or_key` call; losing either shape would let a regression through.
#[test]
fn corpus_covers_both_output_encodings() {
    let coverage = measure_corpus();
    assert!(
        coverage.txs_with_array_output > 0,
        "no Shelley list-encoded outputs left in the corpus"
    );
    assert!(
        coverage.txs_with_map_output > 0,
        "no Babbage map-encoded outputs left in the corpus"
    );
}

/// Array-keyed redeemer maps are the load-bearing Conway shape; the Alonzo list
/// form still appears on chain and still has to parse.
#[test]
fn corpus_covers_both_redeemer_encodings() {
    let coverage = measure_corpus();
    assert!(
        coverage.map_redeemers > 0,
        "no Conway map-encoded redeemer sets left in the corpus"
    );
    assert!(
        coverage.list_redeemers > 0,
        "no Alonzo list-encoded redeemer sets left in the corpus"
    );
}

/// Every body field a validator reads must appear somewhere in the corpus,
/// otherwise the differential tests are checking a path nothing exercises.
#[test]
fn corpus_covers_every_inspected_body_field() {
    let coverage = measure_corpus();
    for (field, name) in [
        (0i128, "inputs"),
        (1, "outputs"),
        (11, "script data hash"),
        (13, "collateral inputs"),
        (14, "required signers"),
        (16, "collateral return"),
        (18, "reference inputs"),
    ] {
        let count = coverage.body_fields.get(&field).copied().unwrap_or(0);
        assert!(
            count > 0,
            "no transaction carries body field {field} ({name})"
        );
    }
}

/// Definite and indefinite lengths are the encoding choice most likely to break
/// a span. Both must stay present, and every indefinite transaction must still
/// hash to its chain id (already asserted above — this only guards the mix).
#[test]
fn corpus_covers_definite_and_indefinite_encodings() {
    let coverage = measure_corpus();
    assert!(
        coverage.indefinite_txs > 0,
        "no transaction uses an indefinite-length container any more"
    );
    assert!(
        coverage.definite_only_txs > 0,
        "no purely definite-length transaction left in the corpus"
    );
    assert!(
        coverage.raw.indefinite_array > 0,
        "indefinite arrays vanished from the corpus"
    );
    assert!(
        coverage.raw.indefinite_bytes > 0,
        "indefinite byte strings vanished from the corpus"
    );
}

/// Major type 1 is covered: six transactions burn tokens, so nine negative
/// quantities sit in body field 9. `as_u64` must refuse every one of them
/// without wrapping.
#[test]
fn corpus_covers_negative_integers() {
    let coverage = measure_corpus();
    assert!(
        coverage.ints.negatives > 0,
        "no negative integers left in the corpus; major type 1 is unexercised"
    );
    assert!(
        coverage.txs_with_negative_ints > 0,
        "no burning transaction left in the corpus"
    );

    // Spot-check the accessor contract on the shape those values take.
    let minus_one = Value::Int(-1);
    assert_eq!(minus_one.as_int(), Some(-1));
    assert_eq!(minus_one.as_u64(), None, "as_u64 must refuse a negative");
}

/// The corpus contains no bignum (tag 2/3) and no positive integer above
/// `u64::MAX`. Multi-asset quantities *can* exceed `u64` on chain, so this is a
/// known gap, recorded rather than papered over: the assertion fires the day a
/// refresh brings one in, which is the day `Value::BigInt` needs a
/// differential case of its own.
#[test]
fn corpus_has_no_bignums_and_no_integers_above_u64() {
    let coverage = measure_corpus();
    assert_eq!(
        coverage.ints.bignums, 0,
        "the corpus grew a bignum; add a differential case for Value::BigInt"
    );
    assert_eq!(
        coverage.ints.above_u64, 0,
        "the corpus grew an integer above u64::MAX; check the as_u64 call sites"
    );
    assert_eq!(
        coverage.raw.tags.get(&2).copied().unwrap_or(0)
            + coverage.raw.tags.get(&3).copied().unwrap_or(0),
        0,
        "bignum tags appeared on the wire"
    );

    // The path the corpus cannot reach, pinned synthetically so the gap is at
    // least described: tag 2 over a 17-byte magnitude exceeds i128 and must
    // land in BigInt, where every u64-shaped accessor refuses it.
    let bytes = hex::decode("c2510100000000000000000000000000000000").expect("hex");
    let value = cbor::decode_exact(&bytes).expect("bignum decodes");
    assert!(
        matches!(
            value,
            Value::BigInt {
                negative: false,
                ..
            }
        ),
        "expected BigInt, got {}",
        value_kind(&value)
    );
    assert_eq!(value.as_u64(), None);
    assert_eq!(value.as_int(), None);
}

/// Major 7 on real wire data is `true` (148) and `null` (88) and nothing else.
/// No `false`, no `undefined`, no simple value, no float — so the corpus can
/// say nothing about how those decode, and it cannot exercise an
/// `is_valid = false` transaction at all. Recorded here so the gap is visible
/// rather than assumed away; the synthetic suites have to cover it.
#[test]
fn corpus_major_seven_is_only_true_and_null() {
    let coverage = measure_corpus();
    let counted = |info: u8| coverage.raw.major7.get(&info).copied().unwrap_or(0);

    assert!(counted(21) > 0, "no `true` left in the corpus");
    assert!(counted(22) > 0, "no `null` left in the corpus");
    // Every four-element envelope in the corpus is a valid transaction, so
    // `true` must account for at least one per envelope.
    assert!(
        counted(21) >= coverage.arity4,
        "fewer `true` values ({}) than four-element envelopes ({})",
        counted(21),
        coverage.arity4
    );
    for (info, name) in [
        (20u8, "false"),
        (23, "undefined"),
        (24, "one-byte simple"),
        (25, "half float"),
        (26, "single float"),
        (27, "double float"),
    ] {
        assert_eq!(
            counted(info),
            0,
            "the corpus grew a major-7 {name}; the synthetic suites' expectations for it are now checkable against real data"
        );
    }
}

/// Nesting must stay far below `MAX_DEPTH`; if a real transaction ever came
/// close, the 256 cap would be a liveness risk rather than a safety net.
#[test]
fn real_nesting_stays_far_below_the_depth_cap() {
    let coverage = measure_corpus();
    assert!(
        coverage.raw.max_depth >= 15,
        "the corpus lost its deeply nested transactions (max depth {})",
        coverage.raw.max_depth
    );
    assert!(
        coverage.raw.max_depth * 4 < cbor::MAX_DEPTH,
        "real nesting ({}) is within 4x of MAX_DEPTH ({})",
        coverage.raw.max_depth,
        cbor::MAX_DEPTH
    );
}

/// Always passes; run with `-- --nocapture` to read the distribution.
#[test]
fn corpus_shape_summary() {
    let coverage = measure_corpus();
    println!("--- chain_corpus.json shape summary ---");
    // 15526 wire nodes, cross-checked against an equivalent raw scan in the
    // repo's cbor2 venv. cbor2's own object graph is smaller (15367) because
    // tag 258 collapses to a `set` and tag 259 to a `dict`, losing the tag node.
    println!(
        "transactions      {} ({} bytes, {} wire nodes)",
        coverage.total, coverage.total_bytes, coverage.raw.nodes
    );
    println!(
        "networks          {:?}  epochs {}..{}",
        coverage.networks, coverage.min_epoch, coverage.max_epoch
    );
    println!(
        "envelope arity    4-element {}  3-element {}",
        coverage.arity4, coverage.arity3
    );
    println!("auxiliary data    {:?}", coverage.aux_kinds);
    println!(
        "input sets        tag-258 {}  untagged array {}",
        coverage.tagged_input_sets, coverage.untagged_input_sets
    );
    println!(
        "outputs           txs with list-encoded {}  txs with map-encoded {}",
        coverage.txs_with_array_output, coverage.txs_with_map_output
    );
    println!(
        "redeemers         map {}  list {}  absent {}",
        coverage.map_redeemers, coverage.list_redeemers, coverage.no_redeemers
    );
    println!(
        "lengths           txs with indefinite {}  definite-only {}",
        coverage.indefinite_txs, coverage.definite_only_txs
    );
    println!(
        "indefinite heads  array {}  map {}  bytes {}  text {}",
        coverage.raw.indefinite_array,
        coverage.raw.indefinite_map,
        coverage.raw.indefinite_bytes,
        coverage.raw.indefinite_text
    );
    println!(
        "integers          bignums {}  above-u64 {}  negative {} (in {} txs, {} major-1 heads)",
        coverage.ints.bignums,
        coverage.ints.above_u64,
        coverage.ints.negatives,
        coverage.txs_with_negative_ints,
        coverage.raw.negative_ints
    );
    println!(
        "max nesting depth {} (MAX_DEPTH {})",
        coverage.raw.max_depth,
        cbor::MAX_DEPTH
    );
    println!("body fields       {:?}", coverage.body_fields);
    println!("tags              {:?}", coverage.raw.tags);
    println!(
        "major-7 by info   {:?} (20 false, 21 true, 22 null, 23 undefined, 25-27 floats)",
        coverage.raw.major7
    );
}

// === the Python fixtures through the same checks ============================

/// The eight Django-suite transactions, measured against the span and id that
/// `cbor2` + `signature.tx_id` produced for them. Same four readings as the
/// chain corpus, so a divergence shows up on the fixtures the Python service
/// is actually tested with.
#[test]
fn python_suite_spans_survive_the_same_checks() {
    let cases = python_suite();
    assert_eq!(cases.len(), 8, "the Python fixture set changed size");

    for case in &cases {
        let bytes = hex::decode(&case.cbor).expect("fixture cbor is hex");
        let label = &case.name;
        let (start, end) = case.body_span;

        // decode_value_raw
        let mut decoder = Decoder::new(&bytes);
        decoder
            .skip_array_header()
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        let (body, raw) = decoder
            .decode_value_raw()
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(
            (decoder.position() - raw.len(), decoder.position()),
            case.body_span,
            "{label}: span disagrees with cbor2"
        );
        assert_eq!(
            raw,
            &bytes[start..end],
            "{label}: raw slice is not a window"
        );

        // skip_value
        assert_eq!(
            decoder_body_span(&bytes).unwrap_or_else(|err| panic!("{label}: {err}")),
            case.body_span,
            "{label}: skip_value span disagrees with decode_value_raw"
        );

        // independent walker
        let (walked, _) = walk_transaction(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(walked, case.body_span, "{label}: walker span disagrees");

        // standalone re-decode
        let standalone = cbor::decode_exact(&bytes[start..end])
            .unwrap_or_else(|err| panic!("{label}: body slice does not stand alone: {err}"));
        assert_eq!(
            standalone, body,
            "{label}: isolated body decodes differently"
        );

        // the digest Python recorded
        assert_eq!(
            hex::encode(signature::blake2b(&bytes[start..end], 32)),
            case.tx_id,
            "{label}: recorded span does not hash to the Python tx id"
        );
        assert!(
            body.as_map().is_some(),
            "{label}: body is {}",
            value_kind(&body)
        );
    }
}

/// The Python fixtures are all four-element Conway envelopes and every body key
/// is an integer; `map_get` must reach each field, duplicates included.
#[test]
fn python_suite_bodies_expose_their_fields() {
    for case in &python_suite() {
        let bytes = hex::decode(&case.cbor).expect("fixture cbor is hex");
        let label = &case.name;
        let envelope = cbor::decode_exact(&bytes).unwrap_or_else(|err| panic!("{label}: {err}"));
        let items = envelope.as_array().expect("array envelope");
        assert_eq!(items.len(), 4, "{label}: envelope arity");
        assert!(
            items[2].as_bool().is_some(),
            "{label}: is_valid is {}",
            value_kind(&items[2])
        );

        let body = &items[0];
        let entries = body.as_map().expect("map body");
        for (key, _) in entries {
            let field = key
                .as_int()
                .unwrap_or_else(|| panic!("{label}: non-integer body key"));
            let last = entries
                .iter()
                .rposition(|(entry_key, _)| entry_key.as_int() == Some(field))
                .expect("present key");
            assert!(
                std::ptr::eq(
                    body.map_get(field).expect("present field"),
                    &entries[last].1
                ),
                "{label}: map_get({field}) is not last-wins"
            );
        }
    }
}
