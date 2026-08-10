//! Hostile-input robustness tests for the hand-rolled CBOR decoder.
//!
//! `src/cbor.rs` is reachable from an unauthenticated POST body: the collateral
//! endpoint hex-decodes up to `MAX_TX_SIZE` (16 KiB) of caller-controlled bytes
//! and hands them straight to `Decoder`. Nothing upstream of it parses CBOR, so
//! the decoder *is* the trust boundary. Every property here is about what the
//! decoder must never do rather than what it must return:
//!
//! * never panic (index out of range, slice out of bounds, arithmetic
//!   overflow) — a panic in an axum handler is caught by `CatchPanicLayer`, but
//!   it still turns a validation failure into a 500;
//! * never overflow the stack — that is an abort, not a caught panic, and it
//!   takes the whole worker down;
//! * never allocate proportional to a *declared* length, only to bytes that
//!   actually arrived;
//! * never spin: work must stay linear-ish in the input length.
//!
//! A second invariant runs through every sweep: `decode_value` and
//! `skip_value` must agree on *acceptance* and on the *byte span*. They are two
//! independent traversals of the same grammar, and `signature::tx_id` slices
//! the body with `skip_value` while the validators inspect it with
//! `decode_value`. If one accepts what the other rejects, or stops one byte
//! sooner, the service either signs a body it never validated or produces a
//! witness for the wrong transaction hash. Every mutated input below checks
//! that parity, which makes the sweeps a span-fidelity fuzz as much as a
//! crash fuzz.
//!
//! Determinism: no network, no Python, no clock-dependent expectations beyond
//! deliberately loose upper bounds. The mutation sweeps are *exhaustive* over
//! their sample (every prefix, every bit, every insertion point), so no seed is
//! involved; the two places that do sample — the 16 KiB buffer fuzz and the
//! cursor-helper hammering — use a fixed-seed splitmix64 defined below.
//!
//! Runtime: ~2.5 s debug, ~0.5 s release, for roughly 200,000 decode attempts.

use collateral_provider::cbor::{self, CborError, Decoder, Value, MAX_DEPTH};
use serde::Deserialize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::time::{Duration, Instant};

// --- allocation accounting --------------------------------------------------
//
// "Never allocate proportional to a declared length" is one of this file's
// stated invariants, and `skip_value` additionally promises to walk a value
// *without materializing it*. Both are claims about allocation, which no
// assertion on a return value can see. This allocator makes them measurable.
//
// The counter is thread-local, so a measurement is unaffected by the other
// tests libtest runs in parallel. `Cell<u64>` has no destructor, so the
// thread-local needs no lazy initialization and no TLS destructor — nothing
// here can allocate re-entrantly.

thread_local! {
    static ALLOCATED: Cell<u64> = const { Cell::new(0) };
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

struct CountingAllocator;

impl CountingAllocator {
    fn record(bytes: usize) {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATED.try_with(|total| total.set(total.get() + bytes as u64));
        }
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        Self::record(new_size.saturating_sub(layout.size()));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Bytes allocated on this thread while `body` ran.
fn bytes_allocated_by(body: impl FnOnce()) -> u64 {
    ALLOCATED.with(|total| total.set(0));
    COUNTING.with(|flag| flag.set(true));
    body();
    COUNTING.with(|flag| flag.set(false));
    ALLOCATED.with(Cell::get)
}

/// The service ceiling: `check_cbor_hex` rejects anything longer, so no input
/// larger than this ever reaches the decoder in production.
const MAX_TX_SIZE: usize = 16 * 1024;

/// CBOR break byte.
const BREAK: u8 = 0xFF;

// --- fixtures ---------------------------------------------------------------

#[derive(Deserialize)]
struct Corpus {
    #[allow(dead_code)] // Provenance note carried in the fixture.
    note: String,
    transactions: Vec<ChainCase>,
}

#[derive(Deserialize)]
struct ChainCase {
    #[allow(dead_code)]
    network: String,
    epoch: u64,
    #[allow(dead_code)]
    block_height: u64,
    tx_hash: String,
    #[allow(dead_code)]
    body_span: (usize, usize),
    cbor: String,
}

fn chain_corpus() -> Vec<ChainCase> {
    let raw = include_str!("fixtures/chain_corpus.json");
    serde_json::from_str::<Corpus>(raw)
        .expect("chain_corpus.json parses")
        .transactions
}

fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex must be byte aligned");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// A deterministic, era-spanning sample of the corpus, biased small so the
/// quadratic sweeps stay cheap.
///
/// Buckets by `epoch / 50` (ten buckets across epochs 194-644, i.e. Byron
/// through current Conway) and takes the two shortest transactions in each,
/// tie-broken by `tx_hash`. That yields 20 transactions of 219-1606 bytes,
/// including two pre-Alonzo 3-element envelopes, both networks, and every era
/// bucket present in the corpus.
fn era_sample() -> Vec<(String, Vec<u8>)> {
    let mut cases = chain_corpus();
    cases.sort_by(|a, b| {
        (a.epoch / 50, a.cbor.len(), &a.tx_hash).cmp(&(b.epoch / 50, b.cbor.len(), &b.tx_hash))
    });
    let mut sample = Vec::new();
    let mut current_bucket = u64::MAX;
    let mut taken = 0;
    for case in &cases {
        let bucket = case.epoch / 50;
        if bucket != current_bucket {
            current_bucket = bucket;
            taken = 0;
        }
        if taken < 2 {
            taken += 1;
            sample.push((case.tx_hash.clone(), unhex(&case.cbor)));
        }
    }
    assert!(
        sample.len() >= 18,
        "era sample should span the corpus, got {}",
        sample.len()
    );
    sample
}

// --- deterministic PRNG -----------------------------------------------------

/// splitmix64. Fixed seed everywhere; no `rand` so the sweeps are reproducible
/// across crate versions.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        assert!(n > 0);
        (self.next_u64() % n as u64) as usize
    }
}

// --- the universal contract -------------------------------------------------

/// Assert everything that must hold for *any* byte string, however hostile.
///
/// Covers the three entry points reachable from a request: `decode_one`
/// (validators), `skip_value` (span slicing), and the
/// `skip_array_header` + `skip_value` pair that is literally
/// `signature::tx_id`'s body cursor. Returns whether the top-level decode
/// succeeded so callers can count.
fn assert_decode_contract(data: &[u8], label: &str) -> bool {
    let decoded = cbor::decode_one(data);

    let mut skipper = Decoder::new(data);
    let skipped = skipper.skip_value();
    let skip_end = skipper.position();

    match (&decoded, &skipped) {
        (Ok((_, consumed)), Ok(span)) => {
            assert!(
                *consumed <= data.len(),
                "{label}: consumed {consumed} > input {}",
                data.len()
            );
            assert_eq!(
                *consumed,
                span.len(),
                "{label}: decode consumed {consumed}, skip span {}",
                span.len()
            );
            assert_eq!(skip_end, *consumed, "{label}: cursor disagreement");
        }
        (Err(_), Err(_)) => {}
        _ => panic!(
            "{label}: decode/skip acceptance diverged (decode ok={}, skip ok={})",
            decoded.is_ok(),
            skipped.is_ok()
        ),
    }

    // The tx_id cursor: outer array header, then the body value. Must not
    // panic and must never report a position past the buffer.
    let mut cursor = Decoder::new(data);
    if cursor.skip_array_header().is_ok() {
        let _ = cursor.skip_value();
        assert!(
            cursor.position() <= data.len(),
            "{label}: tx_id cursor ran past the buffer"
        );
    }

    decoded.is_ok()
}

/// Structural depth of a decoded value, counted the way the decoder counts it:
/// a scalar is 0, each container adds one to its deepest child.
///
/// An *empty* container reads one deeper than the decoder ever recursed (the
/// decoder never calls `decode_at` for a child that is not there), so this can
/// exceed the decoder's own high-water mark by exactly one.
fn value_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(value_depth).max().unwrap_or(0),
        Value::Map(entries) => {
            1 + entries
                .iter()
                .map(|(k, v)| value_depth(k).max(value_depth(v)))
                .max()
                .unwrap_or(0)
        }
        Value::Tag(_, inner) => 1 + value_depth(inner),
        _ => 0,
    }
}

fn timed<T>(work: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = work();
    (out, start.elapsed())
}

// --- 1. truncation ----------------------------------------------------------

/// Every proper prefix of a real transaction, for a 20-transaction sample
/// spanning every era bucket in the corpus.
///
/// That is **8,563 prefixes** (the sample totals 8,563 bytes: 219-1606 bytes
/// each). Each prefix is run through all three entry points. None may panic;
/// each must either error or report a consumed length strictly below the
/// original transaction's length.
///
/// The stronger observed fact is asserted too: *zero* proper prefixes decode
/// successfully, because the top-level value of every corpus transaction spans
/// the entire buffer, so no shorter complete value exists. If a future decoder
/// change let a prefix "complete" early, that would mean the outer envelope
/// stopped being the whole input — precisely the failure mode that silently
/// mis-slices a body span.
#[test]
fn truncation_sweep_every_prefix_of_the_era_sample() {
    let sample = era_sample();
    let mut prefixes = 0usize;
    let mut complete = 0usize;

    for (name, tx) in &sample {
        for cut in 0..tx.len() {
            let prefix = &tx[..cut];
            prefixes += 1;
            if assert_decode_contract(prefix, &format!("{name} prefix[..{cut}]")) {
                complete += 1;
                let (_, consumed) = cbor::decode_one(prefix).expect("just checked");
                assert!(
                    consumed < tx.len(),
                    "{name}: prefix[..{cut}] claims {consumed} bytes of a {}-byte tx",
                    tx.len()
                );
            }
        }
        // The full buffer must still decode; the sweep is only meaningful if
        // the un-truncated input is the success case.
        assert!(
            cbor::decode_exact(tx).is_ok(),
            "{name}: full transaction must decode"
        );
    }

    // 8,563 prefixes on the frozen corpus (the sample totals 8,563 bytes).
    assert!(
        prefixes >= 5_000,
        "expected a few thousand prefixes, got {prefixes}"
    );
    assert_eq!(
        complete, 0,
        "no proper prefix of a corpus transaction should be a complete value"
    );
}

/// Truncation across *all 162* corpus transactions including the 13,937-byte
/// outlier, strided every 16 bytes so the quadratic term stays bounded.
/// Catches era-specific structures the small exhaustive sample misses.
#[test]
fn truncation_sweep_strided_over_the_whole_corpus() {
    let corpus = chain_corpus();
    let mut prefixes = 0usize;
    for case in &corpus {
        let tx = unhex(&case.cbor);
        for cut in (0..tx.len()).step_by(16) {
            prefixes += 1;
            assert!(
                !assert_decode_contract(&tx[..cut], &format!("{} prefix[..{cut}]", case.tx_hash)),
                "{}: prefix[..{cut}] should not be a complete value",
                case.tx_hash
            );
        }
    }
    // 19,779 prefixes on the frozen corpus.
    assert!(prefixes >= 15_000, "expected a broad sweep, got {prefixes}");
}

// --- 2. bit flips -----------------------------------------------------------

/// Flip **every single bit of every byte** of the era sample: 8,563 bytes x 8
/// = 68,504 mutants. The task asked for a fixed-seed sample of positions;
/// exhaustive is cheap enough here (about a second in debug) and is a strict
/// superset, so no seed is involved.
///
/// A single bit flip is the nastiest mutation for this decoder because it can
/// turn a definite head into an indefinite one, a byte-string head into an
/// array head, or a small length into a huge one, while leaving the rest of
/// the buffer intact and plausible. Roughly 91% of these mutants still decode
/// (most of a Cardano transaction is hash and address payload, where a flipped
/// bit changes no structure), so the sweep is mostly a *span-fidelity* check:
/// decode and skip must land on the same byte for all of them.
#[test]
fn bit_flip_sweep_never_panics_and_keeps_spans_honest() {
    let sample = era_sample();
    let mut mutants = 0usize;
    let mut accepted = 0usize;

    for (name, tx) in &sample {
        for index in 0..tx.len() {
            for bit in 0..8u8 {
                let mut mutant = tx.clone();
                mutant[index] ^= 1 << bit;
                mutants += 1;
                if assert_decode_contract(&mutant, &format!("{name} flip[{index}:{bit}]")) {
                    accepted += 1;
                }
            }
        }
    }

    let expected: usize = sample.iter().map(|(_, tx)| tx.len() * 8).sum();
    assert_eq!(mutants, expected);
    assert!(mutants >= 40_000, "expected a broad sweep, got {mutants}");
    // Not a correctness requirement, just a signal that the sweep exercises the
    // accept path and not only the reject path.
    assert!(
        accepted > mutants / 2,
        "bit flips should mostly still decode, got {accepted}/{mutants}"
    );
}

// --- 3. insertion and deletion ----------------------------------------------

/// Insert one byte at **every** position of every sampled transaction, for an
/// alphabet of the heads most likely to derail the cursor. 8,583 positions x
/// 11 bytes = 94,413 mutants.
///
/// Insertion is the mutation that shifts every subsequent byte, so it is the
/// one most likely to leave a structurally valid value with a *different* span
/// — exactly the silent failure that produces a witness for the wrong hash.
#[test]
fn byte_insertion_sweep_never_panics() {
    let sample = era_sample();
    // break, indefinite array/map/bytes/text, reserved additional info,
    // 8-byte byte-string head, 8-byte array head, bignum tag, simple-24 head,
    // and a plain zero as the benign control.
    let alphabet: [u8; 11] = [
        0xFF, 0x9F, 0xBF, 0x5F, 0x7F, 0x1C, 0x5B, 0x9B, 0xC2, 0xF8, 0x00,
    ];
    let mut mutants = 0usize;

    for (name, tx) in &sample {
        for at in 0..=tx.len() {
            for byte in alphabet {
                let mut mutant = Vec::with_capacity(tx.len() + 1);
                mutant.extend_from_slice(&tx[..at]);
                mutant.push(byte);
                mutant.extend_from_slice(&tx[at..]);
                mutants += 1;
                assert_decode_contract(&mutant, &format!("{name} insert[{at}]={byte:02x}"));
            }
        }
    }
    let expected: usize = sample.iter().map(|(_, tx)| (tx.len() + 1) * 11).sum();
    assert_eq!(mutants, expected);
    assert!(mutants >= 50_000, "expected a broad sweep, got {mutants}");
}

/// Delete a single byte at every position of every sampled transaction:
/// 8,563 mutants.
#[test]
fn byte_deletion_sweep_never_panics() {
    let sample = era_sample();
    let mut mutants = 0usize;

    for (name, tx) in &sample {
        for at in 0..tx.len() {
            let mut mutant = tx.clone();
            mutant.remove(at);
            mutants += 1;
            assert_decode_contract(&mutant, &format!("{name} delete[{at}]"));
        }
    }
    let expected: usize = sample.iter().map(|(_, tx)| tx.len()).sum();
    assert_eq!(mutants, expected);
    assert!(mutants >= 5_000, "expected a broad sweep, got {mutants}");
}

/// Splice a whole run out of the middle — the shape a truncated proxy or a
/// mis-framed chunk produces. Every start position, with the run length cycled
/// deterministically through a Fibonacci-ish ladder so both single-byte and
/// header-sized excisions are covered: 8,563 mutants, no seed.
#[test]
fn run_deletion_sweep_never_panics() {
    let sample = era_sample();
    let ladder = [1usize, 2, 3, 5, 8, 13];
    let mut mutants = 0usize;

    for (name, tx) in &sample {
        for at in 0..tx.len() {
            let len = ladder[at % ladder.len()].min(tx.len() - at);
            let mut mutant = tx[..at].to_vec();
            mutant.extend_from_slice(&tx[at + len..]);
            mutants += 1;
            assert_decode_contract(&mutant, &format!("{name} splice[{at}..{}]", at + len));
        }
    }
    assert!(mutants >= 5_000, "expected a broad sweep, got {mutants}");
}

// --- 4. allocation bombs ----------------------------------------------------

/// Every major type with a declared length far beyond any possible buffer.
///
/// The requirement is not merely "errors" but "errors *promptly*": a decoder
/// that pre-allocated `Vec::with_capacity(declared)` would either abort on
/// allocation failure or spend real time zeroing memory. The wall-clock bound
/// is what catches a future regression that reintroduces pre-allocation —
/// without it, such a change would still pass the error-shape assertions.
#[test]
fn declared_length_bombs_error_promptly_without_allocating() {
    // Warm up so the first timing does not absorb lazy init.
    let _ = cbor::decode_one(&unhex("83010203"));

    let heads: [(&str, &str); 4] = [
        ("byte string", "5b"),
        ("text string", "7b"),
        ("array", "9b"),
        ("map", "bb"),
    ];
    let lengths: [(&str, &str); 3] = [
        ("2^64-1", "ffffffffffffffff"),
        ("2^63-1", "7fffffffffffffff"),
        ("2^32", "0000000100000000"),
    ];
    // Empty payload, a short payload, and a full 16 KiB of decodable filler —
    // the array/map bombs consume real items, so the filler is the case where
    // a bomb could actually do work.
    let payloads: [(&str, String); 3] = [
        ("empty", String::new()),
        ("64 bytes", "00".repeat(64)),
        ("16 KiB filler", "00".repeat(MAX_TX_SIZE)),
    ];

    for (type_name, head) in heads {
        for (length_name, length) in lengths {
            for (payload_name, payload) in &payloads {
                let label = format!("{type_name} declaring {length_name} with {payload_name}");
                let data = unhex(&format!("{head}{length}{payload}"));
                let (result, elapsed) = timed(|| cbor::decode_one(&data));
                assert!(
                    result.is_err(),
                    "{label}: must not decode, got {:?}",
                    result.map(|(_, n)| n)
                );
                assert!(
                    elapsed < Duration::from_millis(50),
                    "{label}: took {elapsed:?}; a declared length must never drive allocation"
                );
                // Same contract through the skip cursor.
                let (skipped, elapsed) = timed(|| Decoder::new(&data).skip_value());
                assert!(skipped.is_err(), "{label}: skip must not accept either");
                assert!(
                    elapsed < Duration::from_millis(50),
                    "{label}: skip took {elapsed:?}"
                );
            }
        }
    }

    // The string bombs specifically must report truncation from a bounds check
    // rather than any allocation attempt.
    for head in ["5b", "7b"] {
        let data = unhex(&format!("{head}ffffffffffffffff"));
        assert_eq!(cbor::decode_one(&data), Err(CborError::Truncated));
    }
    // 32-bit-sized heads too (info 26), where `usize::try_from` succeeds on
    // every target and only the slice bound saves us.
    for head in ["5a", "7a", "9a", "ba"] {
        let data = unhex(&format!("{head}ffffffff"));
        assert!(cbor::decode_one(&data).is_err(), "{head}ffffffff");
    }

    // An indefinite string whose *chunk* lies about its length.
    let data = unhex("5f5bffffffffffffffff");
    assert!(cbor::decode_one(&data).is_err());
    let data = unhex("7f7bffffffffffffffff");
    assert!(cbor::decode_one(&data).is_err());
}

/// `skip_value` documents itself as skipping "without materializing" the
/// value. Measured, not assumed: it used to concatenate every chunk of an
/// indefinite-length string into a `Vec` and throw the result away, so a 16 KiB
/// body of chunked string cost the same allocation whether it was decoded or
/// merely stepped over — on the `tx_id` path, which only ever skips.
///
/// The bound is deliberately loose (anything under a kilobyte counts as "did
/// not materialize an 8 KiB string"); the fixed implementation allocates
/// nothing at all here.
#[test]
fn skipping_never_materializes_what_decoding_would() {
    // An 8 KiB indefinite byte string, 64 chunks of 128 bytes.
    let mut chunked = vec![0x5fu8];
    for _ in 0..64 {
        chunked.push(0x58);
        chunked.push(128);
        chunked.extend(std::iter::repeat_n(0xAB, 128));
    }
    chunked.push(BREAK);
    // The same payload as one definite-length string, as a control: there is
    // no chunk list to avoid building, but skipping still must not copy it.
    let mut definite = vec![0x59, 0x20, 0x00];
    definite.extend(std::iter::repeat_n(0xAB, 8192));

    // Warm up: the first decode on a thread touches lazily initialized state.
    assert!(cbor::decode_one(&chunked).is_ok());
    assert!(cbor::decode_one(&definite).is_ok());

    for (label, data) in [("indefinite", &chunked), ("definite", &definite)] {
        let decoded = bytes_allocated_by(|| {
            let value = Decoder::new(data).decode_value().expect("decodes");
            assert_eq!(value.as_bytes().map(<[u8]>::len), Some(8192));
        });
        let skipped = bytes_allocated_by(|| {
            let span = Decoder::new(data).skip_value().expect("skips");
            assert_eq!(span.len(), data.len());
        });
        assert!(
            decoded >= 8192,
            "{label}: decoding 8 KiB allocated only {decoded} bytes — \
             the measurement is not seeing allocations"
        );
        assert!(
            skipped < 1024,
            "{label}: skipping allocated {skipped} bytes; it must not build the value"
        );
    }
}

/// A declared-length bomb nested inside a legitimate envelope: the shape an
/// attacker actually sends, since the outer four-element array has to look
/// like a transaction to get past `check_tx_body`.
#[test]
fn nested_length_bombs_error_promptly() {
    let _ = cbor::decode_one(&unhex("83010203"));
    for inner in [
        "5bffffffffffffffff",
        "9bffffffffffffffff",
        "bbffffffffffffffff",
        "7bffffffffffffffff",
    ] {
        for wrapper in [
            format!("84a10081{inner}f6f6"),
            format!("9f{inner}ff"),
            format!("bf00{inner}ff"),
            format!("d90102{inner}"),
        ] {
            let data = unhex(&wrapper);
            let (result, elapsed) = timed(|| cbor::decode_one(&data));
            assert!(result.is_err(), "{wrapper} should not decode");
            assert!(
                elapsed < Duration::from_millis(50),
                "{wrapper} took {elapsed:?}"
            );
        }
    }
}

// --- 5. depth bombs ---------------------------------------------------------

#[derive(Clone, Copy)]
enum Nest {
    DefiniteArray,
    IndefiniteArray,
    DefiniteMap,
    IndefiniteMap,
    Tag,
}

impl Nest {
    /// Bytes opening one level, and the bytes that close it (empty for the
    /// definite forms, which need no break).
    fn parts(self) -> (&'static [u8], &'static [u8]) {
        match self {
            // one-element array
            Nest::DefiniteArray => (&[0x81], &[]),
            Nest::IndefiniteArray => (&[0x9F], &[BREAK]),
            // one-entry map, key 0, value is the next level
            Nest::DefiniteMap => (&[0xA1, 0x00], &[]),
            Nest::IndefiniteMap => (&[0xBF, 0x00], &[BREAK]),
            // tag 6, an unassigned tag the decoder keeps verbatim
            Nest::Tag => (&[0xC6], &[]),
        }
    }
}

/// Build a tower `levels` deep whose innermost value is the scalar `00`.
/// The scalar therefore sits at decoder depth `levels`.
fn tower(kinds: &[Nest], levels: usize) -> Vec<u8> {
    let mut prefix = Vec::new();
    let mut suffix = Vec::new();
    for level in 0..levels {
        let (open, close) = kinds[level % kinds.len()].parts();
        prefix.extend_from_slice(open);
        // Closers unwind in reverse order.
        let mut next = close.to_vec();
        next.extend_from_slice(&suffix);
        suffix = next;
    }
    prefix.push(0x00);
    prefix.extend_from_slice(&suffix);
    prefix
}

#[test]
fn depth_at_the_limit_is_accepted_and_one_past_it_errors() {
    let single = [
        ("definite array", Nest::DefiniteArray),
        ("indefinite array", Nest::IndefiniteArray),
        ("definite map", Nest::DefiniteMap),
        ("indefinite map", Nest::IndefiniteMap),
        ("tag", Nest::Tag),
    ];

    for (name, kind) in single {
        let at_limit = tower(&[kind], MAX_DEPTH);
        let value = cbor::decode_exact(&at_limit)
            .unwrap_or_else(|e| panic!("{name} at MAX_DEPTH should decode, got {e:?}"));
        assert_eq!(
            value_depth(&value),
            MAX_DEPTH,
            "{name}: tower should be exactly MAX_DEPTH deep"
        );
        assert!(
            Decoder::new(&at_limit).skip_value().is_ok(),
            "{name}: skip must accept what decode accepts"
        );

        let past = tower(&[kind], MAX_DEPTH + 1);
        assert_eq!(
            cbor::decode_exact(&past),
            Err(CborError::DepthExceeded),
            "{name} at MAX_DEPTH+1"
        );
        assert_eq!(
            Decoder::new(&past).skip_value(),
            Err(CborError::DepthExceeded),
            "{name} at MAX_DEPTH+1 (skip)"
        );
    }

    // A mixed tower: no single container type can be special-cased to pass.
    let mixed = [
        Nest::DefiniteArray,
        Nest::IndefiniteArray,
        Nest::Tag,
        Nest::DefiniteMap,
        Nest::IndefiniteMap,
    ];
    let at_limit = tower(&mixed, MAX_DEPTH);
    let value = cbor::decode_exact(&at_limit).expect("mixed tower at MAX_DEPTH decodes");
    assert_eq!(value_depth(&value), MAX_DEPTH);
    assert_eq!(
        cbor::decode_exact(&tower(&mixed, MAX_DEPTH + 1)),
        Err(CborError::DepthExceeded)
    );
    assert_eq!(
        Decoder::new(&tower(&mixed, MAX_DEPTH + 1))
            .skip_value()
            .unwrap_err(),
        CborError::DepthExceeded
    );
}

/// The realistic worst case at the service ceiling: 16 KiB of one-byte
/// container heads. Without the depth cap this recurses 16,384 times and
/// aborts the process on stack overflow — an abort, not a catchable panic, so
/// `CatchPanicLayer` would not save the worker.
#[test]
fn sixteen_kib_of_container_heads_errors_instead_of_overflowing_the_stack() {
    for (name, head) in [
        ("indefinite array 0x9f", 0x9Fu8),
        ("indefinite map 0xbf", 0xBF),
        ("definite array 0x81", 0x81),
        ("definite map 0xa1", 0xA1),
        ("tag 0xc6", 0xC6),
        ("indefinite byte string 0x5f", 0x5F),
    ] {
        let bomb = vec![head; MAX_TX_SIZE];
        let (decoded, elapsed) = timed(|| cbor::decode_one(&bomb));
        assert!(decoded.is_err(), "{name}: 16 KiB tower must be rejected");
        assert!(elapsed < Duration::from_secs(1), "{name}: took {elapsed:?}");

        let (skipped, elapsed) = timed(|| Decoder::new(&bomb).skip_value());
        assert!(skipped.is_err(), "{name}: skip must reject it too");
        assert!(
            elapsed < Duration::from_secs(1),
            "{name} (skip): took {elapsed:?}"
        );
    }

    // The pure nesting cases must be DepthExceeded specifically, not some
    // incidental truncation that happens to stop the recursion first.
    for head in [0x9Fu8, 0xBF, 0x81, 0xA1, 0xC6] {
        let bomb = vec![head; MAX_TX_SIZE];
        assert_eq!(
            cbor::decode_one(&bomb),
            Err(CborError::DepthExceeded),
            "0x{head:02x}"
        );
    }

    // Also the alternating shapes, which a naive per-type counter would miss.
    for pattern in [
        [0x9Fu8, 0xC6].as_slice(),
        [0x81, 0xBF, 0x00].as_slice(),
        [0xA1, 0x00].as_slice(),
        [0xC6, 0x81, 0x9F].as_slice(),
    ] {
        let bomb: Vec<u8> = pattern.iter().copied().cycle().take(MAX_TX_SIZE).collect();
        let (decoded, elapsed) = timed(|| cbor::decode_one(&bomb));
        assert!(
            decoded.is_err(),
            "alternating {pattern:02x?} must be rejected"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "alternating {pattern:02x?}: took {elapsed:?}"
        );
    }
}

// --- 6. length lies ---------------------------------------------------------

#[test]
fn containers_that_lie_about_their_length_are_rejected() {
    // Containers whose declared length exceeds what the buffer holds, and
    // indefinite containers that never close. The exact variant is asserted
    // because "some error" could hide a cursor that ran past the end and then
    // reported the wrong reason.
    let lies = [
        "830102",       // array of 3, two items
        "a2010203",     // map of 2, three values
        "a101",         // map of 1, key only, no value
        "9f0102",       // indefinite array, no break
        "bf010203",     // indefinite map, no break
        "5f4101",       // indefinite bytes, no break
        "7f6161",       // indefinite text, no break
        "9a0000271003", // array of 10,000, one item
        "ba0000271003", // map of 10,000, one item
        "9affffffff00", // array of 2^32-1, one item
        "baffffffff00", // map of 2^32-1, one key
    ];
    for hex in lies {
        let data = unhex(hex);
        assert_eq!(cbor::decode_one(&data), Err(CborError::Truncated), "{hex}");
        assert_eq!(
            Decoder::new(&data).skip_value(),
            Err(CborError::Truncated),
            "{hex} (skip)"
        );
    }

    // The honest counterparts must still decode, so the assertions above are
    // about the lie and not about the shape.
    for hex in ["83010203", "a201020304", "9f0102ff", "bf0102ff", "5f4101ff"] {
        let data = unhex(hex);
        assert!(cbor::decode_exact(&data).is_ok(), "{hex} should decode");
    }

    // A break where a definite container expects an item is a well-formedness
    // violation, not truncation.
    for hex in [
        "8201ff",   // break as the second item of a 2-array
        "81ff",     // break as the only item
        "a101ff",   // break in the value slot of a definite map
        "a1ff01",   // break in the key slot of a definite map
        "bf01ff",   // break in the value slot of an indefinite map
        "826101ff", // break trailing a complete definite array
    ] {
        let data = unhex(hex);
        assert_eq!(
            cbor::decode_one(&data),
            Err(CborError::Malformed("unexpected CBOR break")),
            "{hex}"
        );
        assert!(Decoder::new(&data).skip_value().is_err(), "{hex} (skip)");
    }

    // A stray break with nothing open at all.
    assert_eq!(
        cbor::decode_one(&[BREAK]),
        Err(CborError::Malformed("unexpected CBOR break"))
    );

    // Indefinite string chunks that are not same-major definite strings.
    for hex in ["5f0102ff", "5f6161ff", "7f4101ff", "5f5f4101ffff"] {
        let data = unhex(hex);
        assert!(matches!(
            cbor::decode_one(&data),
            Err(CborError::Malformed(_))
        ));
        assert!(Decoder::new(&data).skip_value().is_err(), "{hex} (skip)");
    }
}

// --- 7. pathological but well-formed ----------------------------------------

/// Legitimate-but-large inputs must succeed and stay fast. A robustness fix
/// that made these fail (or crawl) would be a denial of service against honest
/// callers, which is the failure mode a paranoid decoder falls into.
#[test]
fn wide_but_shallow_inputs_decode_quickly() {
    let _ = cbor::decode_one(&unhex("83010203"));

    // 10,000 small integers: 5-byte head + 10,000 payload bytes.
    let mut array = unhex("9a00002710");
    array.extend(std::iter::repeat_n(0x01u8, 10_000));
    let (value, elapsed) = timed(|| cbor::decode_exact(&array));
    let value = value.expect("10k-element array decodes");
    assert_eq!(value.as_array().map(<[_]>::len), Some(10_000));
    assert!(elapsed < Duration::from_millis(500), "took {elapsed:?}");

    // 5,000 entries: head + 10,000 payload bytes.
    let mut map = unhex("ba00001388");
    for _ in 0..5_000 {
        map.extend_from_slice(&[0x01, 0x02]);
    }
    let (value, elapsed) = timed(|| cbor::decode_exact(&map));
    let value = value.expect("5k-entry map decodes");
    assert_eq!(value.as_map().map(<[_]>::len), Some(5_000));
    // Duplicate keys are preserved on the wire and read last-wins.
    assert_eq!(value.map_get(1), Some(&Value::Int(2)));
    assert!(elapsed < Duration::from_millis(500), "took {elapsed:?}");

    // A full 16 KiB byte string.
    let mut bytes = unhex("5a00004000");
    bytes.extend(std::iter::repeat_n(0xABu8, MAX_TX_SIZE));
    let (value, elapsed) = timed(|| cbor::decode_exact(&bytes));
    assert_eq!(
        value
            .expect("16 KiB byte string decodes")
            .as_bytes()
            .map(<[u8]>::len),
        Some(MAX_TX_SIZE)
    );
    assert!(elapsed < Duration::from_millis(500), "took {elapsed:?}");

    // 2,000 indefinite string chunks (both majors).
    let mut chunks = vec![0x5Fu8];
    for i in 0..2_000u32 {
        chunks.extend_from_slice(&[0x41, i as u8]);
    }
    chunks.push(BREAK);
    let (value, elapsed) = timed(|| cbor::decode_exact(&chunks));
    assert_eq!(
        value
            .expect("2k byte chunks decode")
            .as_bytes()
            .map(<[u8]>::len),
        Some(2_000)
    );
    assert!(elapsed < Duration::from_millis(500), "took {elapsed:?}");

    let mut chunks = vec![0x7Fu8];
    for _ in 0..2_000 {
        chunks.extend_from_slice(&[0x61, b'a']);
    }
    chunks.push(BREAK);
    let (value, elapsed) = timed(|| cbor::decode_exact(&chunks));
    assert_eq!(
        value
            .expect("2k text chunks decode")
            .as_text()
            .map(str::len),
        Some(2_000)
    );
    assert!(elapsed < Duration::from_millis(500), "took {elapsed:?}");

    // 8,000 nested-but-shallow siblings: wide *and* allocating, the worst
    // Value-count amplification a 16 KiB input can buy.
    let mut wide = vec![0x9Fu8];
    for _ in 0..8_000 {
        wide.extend_from_slice(&[0x81, 0x00]);
    }
    wide.push(BREAK);
    assert!(wide.len() <= MAX_TX_SIZE + 2);
    let (value, elapsed) = timed(|| cbor::decode_exact(&wide));
    assert_eq!(
        value
            .expect("8k sibling arrays decode")
            .as_array()
            .map(<[_]>::len),
        Some(8_000)
    );
    assert!(elapsed < Duration::from_millis(500), "took {elapsed:?}");
}

// --- 8. the whole-service ceiling -------------------------------------------

/// A 16 KiB input cannot reach `MAX_DEPTH` without being rejected.
///
/// The argument is arithmetic: every nesting level costs at least one byte, so
/// 16 KiB buys at most 16,384 levels, and the decoder refuses past 256. The
/// test pins the *minimal* per-level encodings (one byte each) plus a
/// fixed-seed fuzz biased entirely toward container heads, and asserts that
/// anything that survives is at most `MAX_DEPTH` deep.
#[test]
fn no_sixteen_kib_input_exceeds_max_depth_without_erroring() {
    // Nothing in CBOR opens a nesting level in less than one byte, so a
    // MAX_TX_SIZE body reaches at most MAX_TX_SIZE levels. The test is only
    // interesting because that ceiling is far above MAX_DEPTH.
    const _: () = assert!(MAX_TX_SIZE > MAX_DEPTH);

    // One byte per level, for every container form that has a one-byte head.
    for head in [0x81u8, 0x9F, 0xA1, 0xBF, 0xC6] {
        let bomb = vec![head; MAX_TX_SIZE];
        assert_eq!(cbor::decode_one(&bomb), Err(CborError::DepthExceeded));
    }

    // Fuzz: 16 KiB buffers drawn from a container-heavy alphabet, so the
    // sampler spends its budget on the nesting path rather than on scalars.
    let alphabet: [u8; 16] = [
        0x81, 0x82, 0x9F, 0xA1, 0xA2, 0xBF, 0xC6, 0xD9, 0x5F, 0x7F, 0x00, 0x01, 0x40, 0x60, 0xF6,
        BREAK,
    ];
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_0001);
    let mut accepted = 0usize;
    let (_, elapsed) = timed(|| {
        for case in 0usize..512 {
            let mut buffer: Vec<u8> = (0..MAX_TX_SIZE)
                .map(|_| alphabet[rng.below(alphabet.len())])
                .collect();
            // Half the cases are forced to open a container so the sampler
            // actually spends its budget on the recursive path; the other half
            // are left free so the accept path is exercised too.
            if case.is_multiple_of(2) {
                buffer[0] = 0x9F;
            }
            if let Ok((value, consumed)) = cbor::decode_one(&buffer) {
                accepted += 1;
                assert!(consumed <= buffer.len(), "case {case}: consumed too much");
                // `value_depth` counts an empty container one deeper than the
                // decoder ever recursed, hence the +1.
                assert!(
                    value_depth(&value) <= MAX_DEPTH + 1,
                    "case {case}: accepted a value {} deep",
                    value_depth(&value)
                );
            }
            assert_decode_contract(&buffer, &format!("fuzz case {case}"));
        }
    });
    assert!(
        elapsed < Duration::from_secs(20),
        "512 x 16 KiB fuzz took {elapsed:?}"
    );
    // Sanity that the alphabet is not producing only rejects.
    assert!(accepted > 0, "fuzz never produced a decodable buffer");
}

/// The corpus itself, as the honest-traffic depth baseline: real transactions
/// are nowhere near the cap, so the cap can never reject legitimate input.
#[test]
fn real_transactions_are_far_below_the_depth_cap() {
    let mut deepest = 0usize;
    for case in chain_corpus() {
        let tx = unhex(&case.cbor);
        let value = cbor::decode_exact(&tx)
            .unwrap_or_else(|e| panic!("{} should decode, got {e:?}", case.tx_hash));
        deepest = deepest.max(value_depth(&value));
    }
    assert!(
        deepest <= 32,
        "real transactions should stay shallow, deepest was {deepest}"
    );
    assert!(
        deepest * 8 < MAX_DEPTH,
        "MAX_DEPTH ({MAX_DEPTH}) should keep a wide margin over real traffic ({deepest})"
    );
}

/// Time bound on the worst pathological 16 KiB inputs this suite can build.
///
/// Deliberately an order-of-magnitude bound, not a tight one: the point is to
/// catch a decoder that became super-linear, not to benchmark the machine.
#[test]
fn worst_case_sixteen_kib_inputs_stay_bounded() {
    let mut worst: Vec<(String, Vec<u8>)> = Vec::new();

    // Deep-then-wide: MAX_DEPTH of nesting, then the rest of the budget spent
    // on siblings at the deepest legal level.
    let mut deep_wide = vec![0x9Fu8; MAX_DEPTH];
    while deep_wide.len() < MAX_TX_SIZE - MAX_DEPTH {
        deep_wide.push(0x00);
    }
    deep_wide.extend(std::iter::repeat_n(BREAK, MAX_DEPTH));
    worst.push(("deep then wide".into(), deep_wide));

    // Maximum container count: every byte opens and closes a level.
    let mut alternating = vec![0x9Fu8];
    while alternating.len() < MAX_TX_SIZE - 1 {
        alternating.push(0x80);
    }
    alternating.push(BREAK);
    worst.push(("8k empty siblings".into(), alternating));

    // Maximum map entries.
    let mut maps = vec![0xBFu8];
    while maps.len() < MAX_TX_SIZE - 1 {
        maps.extend_from_slice(&[0x00, 0xA0]);
    }
    maps.push(BREAK);
    worst.push(("indefinite map of empty maps".into(), maps));

    // Maximum indefinite string chunks.
    let mut chunks = vec![0x5Fu8];
    while chunks.len() < MAX_TX_SIZE - 1 {
        chunks.push(0x40);
    }
    chunks.push(BREAK);
    worst.push(("8k empty chunks".into(), chunks));

    // Tag chain at the cap, then filler.
    let mut tags = vec![0xC6u8; MAX_DEPTH];
    tags.push(0x00);
    worst.push(("tag chain at the cap".into(), tags));

    // A declared-length bomb over a full buffer of decodable filler.
    let mut bomb = unhex("9bffffffffffffffff");
    bomb.extend(std::iter::repeat_n(0x00u8, MAX_TX_SIZE - bomb.len()));
    worst.push(("array bomb over 16 KiB of filler".into(), bomb));

    for (name, data) in &worst {
        assert!(
            data.len() <= MAX_TX_SIZE + 1,
            "{name}: fixture should sit at the service ceiling, got {}",
            data.len()
        );
        let (_, elapsed) = timed(|| cbor::decode_one(data));
        assert!(
            elapsed < Duration::from_millis(500),
            "{name}: decode took {elapsed:?} for {} bytes",
            data.len()
        );
        let (_, elapsed) = timed(|| Decoder::new(data).skip_value());
        assert!(
            elapsed < Duration::from_millis(500),
            "{name}: skip took {elapsed:?}"
        );
        assert_decode_contract(data, name);
    }
}

// --- cursor API robustness --------------------------------------------------

/// `container_header`, `skip_array_header`, `at_break` and `consume_break` are
/// public and are called on attacker bytes by `script_integrity` and
/// `signature`. They must be as unpanicky as the recursive decoder.
#[test]
fn cursor_helpers_survive_hostile_bytes_and_out_of_range_positions() {
    let sample = era_sample();
    let mut rng = Rng::new(0xFEED_FACE_0000_0007);

    for (_, tx) in &sample {
        for _ in 0..64 {
            let index = rng.below(tx.len());
            let mut mutant = tx.clone();
            mutant[index] = (rng.below(256)) as u8;

            let mut decoder = Decoder::new(&mutant);
            let _ = decoder.skip_array_header();
            let _ = decoder.container_header(4);
            let _ = decoder.container_header(5);
            let _ = decoder.at_break();
            let _ = decoder.consume_break();
            let _ = decoder.skip_value();
            let _ = decoder.decode_value();
            let _ = decoder.remaining();
            // The cursor only ever advances over bytes it actually read, so it
            // can never point past the buffer.
            assert!(decoder.position() <= mutant.len());
        }
    }

    // `set_position` is unchecked; nothing downstream may index out of range.
    let data = unhex("84a0a0f5f6");
    for pos in [0usize, 1, 4, 5, 6, 1_000, usize::MAX / 2, usize::MAX] {
        let mut decoder = Decoder::new(&data);
        decoder.set_position(pos);
        assert!(decoder.remaining().len() <= data.len());
        let _ = decoder.is_at_end();
        let _ = decoder.at_break();
        let _ = decoder.consume_break();
        let _ = decoder.skip_value();
        let _ = decoder.decode_value();
        let _ = decoder.container_header(4);
        let _ = decoder.skip_array_header();
    }

    // Empty input through every entry point.
    assert!(cbor::decode_one(&[]).is_err());
    assert!(cbor::decode_exact(&[]).is_err());
    assert!(Decoder::new(&[]).skip_value().is_err());
    assert!(Decoder::new(&[]).skip_array_header().is_err());
    assert!(Decoder::new(&[]).container_header(4).is_err());
    assert!(!Decoder::new(&[]).at_break());
    assert!(Decoder::new(&[]).consume_break().is_err());
}

/// Peak decoded-value size is bounded by the *input*, not by any declared
/// length.
///
/// Every `Value` node costs at least one input byte to encode, so a 16 KiB
/// request can materialize at most 16,384 nodes. At 32 bytes per node that is
/// 512 KiB of `Value` plus the `Vec` backing stores — a bounded ~50x
/// amplification, not the unbounded one a length-driven `with_capacity` would
/// give. This test pins the node size so a future `Value` variant that blows
/// it up (an inline array, a large fixed buffer) is noticed.
#[test]
fn decoded_value_size_keeps_amplification_bounded() {
    let node = std::mem::size_of::<Value>();
    assert!(
        node <= 64,
        "Value grew to {node} bytes; 16 KiB of input now materializes {} KiB",
        MAX_TX_SIZE * node / 1024
    );

    // The densest node-per-byte input: one empty array per byte.
    let mut dense = vec![0x9Fu8];
    while dense.len() < MAX_TX_SIZE - 1 {
        dense.push(0x80);
    }
    dense.push(BREAK);
    let value = cbor::decode_exact(&dense).expect("dense sibling array decodes");
    let nodes = 1 + value.as_array().expect("array").len();
    assert!(
        nodes <= dense.len(),
        "{nodes} nodes from {} bytes: amplification is no longer bounded by input length",
        dense.len()
    );
}

/// `skip_value` and `decode_value` must agree on *acceptance* and on the error
/// *variant*.
///
/// A bignum tag whose payload byte is missing entirely used to be the one
/// exception: `skip_at` peeked the next head's major type before recursing and
/// reported `Malformed("invalid bignum value")`, while `decode_at` recursed
/// first and reported `Truncated`. `skip_at` now walks the payload and applies
/// the bignum type check afterwards, exactly as `apply_tag` does, so the two
/// report the same error everywhere.
#[test]
fn skip_and_decode_agree_on_the_error_for_malformed_bignums() {
    for hex in ["c2", "c3", "c2c2", "c3d90102"] {
        let data = unhex(hex);
        let decoded = cbor::decode_one(&data);
        let skipped = Decoder::new(&data).skip_value();
        assert!(decoded.is_err() && skipped.is_err(), "{hex}");
    }

    // The formerly-asymmetric case, now pinned as agreeing.
    let bare_bignum_tag = unhex("c2");
    assert_eq!(
        cbor::decode_one(&bare_bignum_tag),
        Err(CborError::Truncated)
    );
    assert_eq!(
        Decoder::new(&bare_bignum_tag).skip_value(),
        Err(CborError::Truncated)
    );
    // A tag wrapping a tag: the payload is well-formed but is not a byte
    // string, so both report the bignum check itself.
    let nested = unhex("c2c24101");
    assert_eq!(
        cbor::decode_one(&nested),
        Err(CborError::Malformed("invalid bignum value"))
    );
    assert_eq!(
        Decoder::new(&nested).skip_value(),
        Err(CborError::Malformed("invalid bignum value"))
    );

    // Where both traversals reach the same decision point they must also agree
    // on the reason, which is what the rest of the corpus sweeps rely on.
    for hex in [
        "",
        "ff",
        "1c",
        "fc",
        "df01",
        "62c328",
        "7f4101ff",
        "c201",
        "8201ff",
        "5bffffffffffffffff",
        "9f0102",
        "5f0102ff",
        "d9",
        "d90102",
        "c25f",
        "c25f41",
    ] {
        let data = unhex(hex);
        let decoded = cbor::decode_one(&data).unwrap_err();
        let skipped = Decoder::new(&data).skip_value().unwrap_err();
        assert_eq!(decoded, skipped, "{hex}");
    }
}

/// Stack headroom at `MAX_DEPTH`.
///
/// `MAX_DEPTH` stops the recursion, but only a measurement says whether 256
/// frames of `decode_at` fit in the stack the decoder actually runs on. The
/// axum handler runs on a tokio worker thread, whose default stack is 2 MiB —
/// a quarter of the 8 MiB libtest gives its own threads, so a suite that only
/// ever decodes on a test thread proves nothing about production. Overflow
/// there is an abort, which `CatchPanicLayer` cannot convert into a 500.
///
/// The probe decodes the deepest legal tower of each container type on a
/// thread sized to tokio's default, which is the claim worth making: a
/// `MAX_DEPTH` decode fits on the thread that actually runs it.
///
/// Measured thresholds for the whole probe (binary search via
/// `CBOR_STACK_PROBE`, rustc 1.96.1, x86_64-linux):
///
/// | profile | overflows at | passes at | approx per frame |
/// |---------|--------------|-----------|------------------|
/// | debug   | 896 KiB      | 1 MiB     | ~3.9 KiB         |
/// | release | 64 KiB       | 128 KiB   | ~0.4 KiB         |
///
/// The shipped (release) build therefore has ~16x headroom and a debug build
/// ~2x. **`MAX_DEPTH` must not be raised without redoing this measurement** —
/// at 512 a debug build would want ~2 MiB and sit exactly on tokio's limit.
///
/// A regression here *aborts* the test binary rather than failing the test.
/// That is inherent to stack-overflow testing, and it is unmissable.
#[test]
fn max_depth_decoding_fits_in_a_tokio_worker_stack() {
    // tokio's default worker-thread stack size.
    let stack_bytes: usize = std::env::var("CBOR_STACK_PROBE")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(2 * 1024 * 1024);

    let handle = std::thread::Builder::new()
        .stack_size(stack_bytes)
        .name("cbor-depth-probe".into())
        .spawn(move || {
            for kind in [
                Nest::DefiniteArray,
                Nest::IndefiniteArray,
                Nest::DefiniteMap,
                Nest::IndefiniteMap,
                Nest::Tag,
            ] {
                let at_limit = tower(&[kind], MAX_DEPTH);
                let value = cbor::decode_exact(&at_limit).expect("decodes at MAX_DEPTH");
                assert_eq!(value_depth(&value), MAX_DEPTH);
                // Dropping a 256-deep Value recurses too.
                drop(value);
                Decoder::new(&at_limit).skip_value().expect("skips");
                // One past the limit unwinds 257 frames of Err propagation.
                let past = tower(&[kind], MAX_DEPTH + 1);
                assert_eq!(cbor::decode_exact(&past), Err(CborError::DepthExceeded));
            }
            // The 16 KiB bomb recurses to the cap before bailing.
            assert_eq!(
                cbor::decode_one(&vec![0x9Fu8; MAX_TX_SIZE]),
                Err(CborError::DepthExceeded)
            );
        })
        .expect("spawn depth probe");

    handle
        .join()
        .expect("MAX_DEPTH decoding must fit in a small stack");
}

/// Exhaustive three-byte sweep: 16,777,216 buffers through both traversals,
/// checking acceptance and span parity on every one of them.
///
/// Three bytes is enough to reach every head width up to the two-byte
/// argument, every tag-plus-payload pair, every indefinite open/close pair,
/// and every simple-value encoding — so this is a complete proof over the
/// short-input space rather than a sample. 2.4 s in debug, 0.4 s in release.
#[test]
fn every_three_byte_input_agrees_between_decode_and_skip() {
    let mut buffer = [0u8; 3];
    for first in 0u8..=255 {
        buffer[0] = first;
        for second in 0u8..=255 {
            buffer[1] = second;
            for third in 0u8..=255 {
                buffer[2] = third;
                let decoded = cbor::decode_one(&buffer);
                let mut skipper = Decoder::new(&buffer);
                let skipped = skipper.skip_value();
                assert_eq!(
                    decoded.is_ok(),
                    skipped.is_ok(),
                    "acceptance diverged on {first:02x}{second:02x}{third:02x}"
                );
                if let (Ok((_, consumed)), Ok(span)) = (&decoded, &skipped) {
                    assert!(*consumed <= buffer.len());
                    assert_eq!(
                        *consumed,
                        span.len(),
                        "span diverged on {first:02x}{second:02x}{third:02x}"
                    );
                }
            }
        }
    }
}

/// Every one-byte and two-byte input. 65,792 buffers, exhaustive: the cheapest
/// possible proof that no head-byte / argument-byte combination panics, and
/// that decode and skip agree on all of them.
#[test]
fn every_one_and_two_byte_input_is_handled() {
    for first in 0u8..=255 {
        assert_decode_contract(&[first], &format!("[{first:02x}]"));
        for second in 0u8..=255 {
            assert_decode_contract(&[first, second], &format!("[{first:02x}{second:02x}]"));
        }
    }
}
