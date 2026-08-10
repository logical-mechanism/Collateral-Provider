//! Differential tests against the Python implementation and the real chain.
//!
//! The signing path hashes the transaction body's *exact wire byte span*, so
//! the one thing a port can silently get wrong is where that span starts and
//! ends. A re-serializing decoder passes every structural unit test and still
//! produces witnesses that no node accepts.
//!
//! Two corpora pin it down:
//!
//! * `python_suite.json` — transactions lifted from the Django test suite,
//!   with the body span and tx id as computed by `cbor2` + `signature.tx_id`.
//!   Rust must agree byte for byte.
//! * `chain_corpus.json` — 162 real transactions harvested from Koios across
//!   both networks. Each `tx_hash` is the id the chain itself assigned, which
//!   makes the corpus an oracle no implementation can talk its way out of.

use collateral_provider::cbor::{self, Decoder};
use collateral_provider::script_integrity;
use collateral_provider::signature;
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus<T> {
    #[allow(dead_code)] // Provenance note carried in the fixture, not asserted on.
    note: String,
    transactions: Vec<T>,
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

fn python_suite() -> Vec<PythonCase> {
    let raw = include_str!("fixtures/python_suite.json");
    serde_json::from_str::<Corpus<PythonCase>>(raw)
        .expect("python_suite.json parses")
        .transactions
}

fn chain_corpus() -> Vec<ChainCase> {
    let raw = include_str!("fixtures/chain_corpus.json");
    serde_json::from_str::<Corpus<ChainCase>>(raw)
        .expect("chain_corpus.json parses")
        .transactions
}

/// Recover the body's byte span the same way `signature::tx_id` does.
///
/// `tx_id` returns only the digest, so the span itself is recomputed here
/// through the same public decoder calls. If these two ever diverge the tx-id
/// assertions below still catch it — the digest is over exactly this slice.
fn body_span(tx_bytes: &[u8]) -> Result<(usize, usize), String> {
    let mut decoder = Decoder::new(tx_bytes);
    decoder.skip_array_header().map_err(|e| e.to_string())?;
    let start = decoder.position();
    decoder.skip_value().map_err(|e| e.to_string())?;
    Ok((start, decoder.position()))
}

#[test]
fn python_suite_body_spans_match_cbor2() {
    let cases = python_suite();
    assert!(!cases.is_empty(), "fixture must not be empty");

    for case in &cases {
        let bytes = hex::decode(&case.cbor).expect("fixture cbor is hex");
        let span = body_span(&bytes).unwrap_or_else(|err| panic!("{}: {err}", case.name));
        assert_eq!(
            span, case.body_span,
            "{}: body span disagrees with cbor2",
            case.name
        );
    }
}

#[test]
fn python_suite_tx_ids_match() {
    for case in &python_suite() {
        let got = signature::tx_id(&case.cbor).unwrap_or_else(|err| panic!("{}: {err}", case.name));
        assert_eq!(
            got, case.tx_id,
            "{}: tx id disagrees with Python",
            case.name
        );
    }
}

/// The chain assigned these ids, so this is the assertion that actually
/// protects the witness: `blake2b256(body span)` must reproduce `tx_hash`.
#[test]
fn chain_corpus_tx_ids_match_the_ledger() {
    let cases = chain_corpus();
    assert!(
        cases.len() >= 100,
        "corpus shrank unexpectedly: {} entries",
        cases.len()
    );

    for case in &cases {
        let label = format!("{} epoch {} {}", case.network, case.epoch, case.tx_hash);
        let got = signature::tx_id(&case.cbor).unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(got, case.tx_hash, "{label}: computed id is not the chain's");
    }
}

#[test]
fn chain_corpus_body_spans_match_the_recorded_offsets() {
    for case in &chain_corpus() {
        let bytes = hex::decode(&case.cbor).expect("fixture cbor is hex");
        let span = body_span(&bytes).unwrap_or_else(|err| panic!("{}: {err}", case.tx_hash));
        assert_eq!(span, case.body_span, "{}: body span drifted", case.tx_hash);
    }
}

/// The span must be a slice of the input, never a re-encoding: hashing the
/// recorded offsets directly has to give the same answer as `tx_id`.
#[test]
fn chain_corpus_hashes_the_submitted_bytes_verbatim() {
    for case in &chain_corpus() {
        let bytes = hex::decode(&case.cbor).expect("fixture cbor is hex");
        let (start, end) = case.body_span;
        let direct = hex::encode(signature::blake2b(&bytes[start..end], 32));
        assert_eq!(
            direct, case.tx_hash,
            "{}: recorded span does not hash to the chain id",
            case.tx_hash
        );
    }
}

/// Every real transaction must decode fully, with no trailing bytes — the
/// decoder is not allowed to stop early and still call the input well-formed.
#[test]
fn chain_corpus_decodes_exactly() {
    for case in &chain_corpus() {
        let bytes = hex::decode(&case.cbor).expect("fixture cbor is hex");
        let value =
            cbor::decode_exact(&bytes).unwrap_or_else(|err| panic!("{}: {err}", case.tx_hash));
        let items = value
            .as_array()
            .unwrap_or_else(|| panic!("{}: transaction is not an array", case.tx_hash));
        assert!(
            items.len() == 4 || items.len() == 3,
            "{}: unexpected envelope arity {}",
            case.tx_hash,
            items.len()
        );
    }
}

/// `script_data_parts` walks the same transactions with an independent cursor.
/// Where it succeeds it must agree with the general decoder about the redeemer
/// bytes; where it fails it must fail cleanly rather than panic.
#[test]
fn script_data_parts_agrees_with_the_general_decoder() {
    let mut parsed = 0usize;
    for case in &chain_corpus() {
        let bytes = hex::decode(&case.cbor).expect("fixture cbor is hex");
        let Ok((_committed, redeemers, _datums)) = script_integrity::script_data_parts(&case.cbor)
        else {
            // Pre-Conway envelopes and transactions whose witness set uses a
            // shape this cursor rejects are handled by the ordinary
            // validators; the contract here is only "no panic".
            continue;
        };
        parsed += 1;

        if redeemers.is_empty() {
            continue;
        }
        // The extracted bytes must be a verbatim substring of the input, and
        // must decode on their own.
        let needle = redeemers.as_slice();
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "{}: redeemer bytes are not a slice of the transaction",
            case.tx_hash
        );
        cbor::decode_exact(needle)
            .unwrap_or_else(|err| panic!("{}: redeemer bytes do not decode: {err}", case.tx_hash));
    }
    assert!(
        parsed > 0,
        "script_data_parts parsed nothing in the whole corpus"
    );
}

/// Nothing in the corpus may be turned away for *structural* reasons.
///
/// `script_data_parts` rejects plenty of these transactions, but every
/// rejection has to be a semantic one — no script data hash, no redeemers, or
/// a pre-Conway three-element envelope. A decode-level message ("truncated
/// CBOR", "invalid CBOR value", "trailing CBOR data") against a transaction
/// the chain accepted would mean the cursor, not the transaction, is wrong.
#[test]
fn corpus_rejections_are_all_semantic() {
    use std::collections::BTreeMap;

    let semantic = [
        "transaction has no redeemers",
        "transaction has no valid script data hash",
        "transaction must have four elements",
    ];

    let cases = chain_corpus();
    let mut accepted = 0usize;
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();

    for case in &cases {
        match script_integrity::script_data_parts(&case.cbor) {
            Ok((committed, redeemers, _datums)) => {
                accepted += 1;
                assert_eq!(
                    committed.len(),
                    32,
                    "{}: script data hash is not 32 bytes",
                    case.tx_hash
                );
                assert!(
                    !redeemers.is_empty(),
                    "{}: accepted with empty redeemers",
                    case.tx_hash
                );
            }
            Err(err) => {
                let message = err.to_string();
                assert!(
                    semantic.contains(&message.as_str()),
                    "{}: structural decode failure on a transaction the chain accepted: {message}",
                    case.tx_hash
                );
                *reasons.entry(message).or_default() += 1;
            }
        }
    }

    // Guard against the corpus quietly degenerating into all-rejections.
    assert!(
        accepted >= 50,
        "only {accepted} of {} transactions carried script data",
        cases.len()
    );
}

/// Every hex entry point has to accept exactly the strings `check_cbor_hex`
/// accepts, or the service refuses a request the Django one signs.
///
/// The pipeline validates `check_cbor_hex`'s decoded bytes but then hands the
/// *original string* to three more consumers — the redeemer-budget reader, the
/// script-data cursor, and the signer. Each used to re-decode it with
/// `hex::decode`, which rejects the ASCII whitespace `bytes.fromhex` skips, so
/// a pretty-printed transaction passed validation and then died with
/// "Invalid CBOR Data In Tx". Running the whole chain corpus through a
/// whitespace-injected form pins every one of them to the same decoder.
#[test]
fn every_hex_entry_point_accepts_what_bytes_fromhex_accepts() {
    use collateral_provider::validators::cbor::check_cbor_hex;
    use collateral_provider::validators::transaction::committed_redeemer_budgets;

    /// A space after every byte, plus leading and trailing whitespace —
    /// `bytes.fromhex` accepts all of it, `hex::decode` accepts none of it.
    fn spaced(hex: &str) -> String {
        let mut out = String::from("\n ");
        for pair in hex.as_bytes().chunks(2) {
            out.push_str(std::str::from_utf8(pair).expect("ascii hex"));
            out.push(' ');
        }
        out.push('\t');
        out
    }

    // The cap only has to admit the corpus; the point here is the decoder.
    const CAP: usize = 1 << 20;
    let mut budget_cases = 0usize;
    let mut script_data_cases = 0usize;

    for case in &chain_corpus() {
        let label = &case.tx_hash;
        let padded = spaced(&case.cbor);

        // 1. The gate the pipeline actually runs first.
        let bytes = check_cbor_hex(&padded, CAP).unwrap_or_else(|err| {
            panic!(
                "{label}: check_cbor_hex rejected padded hex: {}",
                err.detail()
            )
        });
        assert_eq!(
            hex::encode(&bytes),
            case.cbor.to_lowercase(),
            "{label}: padded hex decoded to different bytes"
        );

        // 2. The signer, whose answer is the transaction id the chain assigned.
        assert_eq!(
            signature::tx_id(&padded).unwrap_or_else(|err| panic!("{label}: {err}")),
            case.tx_hash,
            "{label}: padded hex produced a different transaction id"
        );

        // 3. and 4. The two consumers inside `check_valid_tx`. Both legitimately
        // reject some corpus entries on semantic grounds; what may never differ
        // is their verdict between the padded and clean forms.
        let clean_budgets = committed_redeemer_budgets(&case.cbor);
        let padded_budgets = committed_redeemer_budgets(&padded);
        match (&clean_budgets, &padded_budgets) {
            (Ok(clean), Ok(padded)) => {
                assert_eq!(clean, padded, "{label}: budgets differ");
                budget_cases += 1;
            }
            (Err(clean), Err(padded)) => {
                assert_eq!(
                    clean.detail(),
                    padded.detail(),
                    "{label}: budget errors differ"
                )
            }
            _ => panic!("{label}: whitespace flipped the redeemer-budget verdict"),
        }

        let clean_parts = script_integrity::script_data_parts(&case.cbor);
        let padded_parts = script_integrity::script_data_parts(&padded);
        match (&clean_parts, &padded_parts) {
            (Ok(clean), Ok(padded)) => {
                assert_eq!(clean, padded, "{label}: script data parts differ");
                script_data_cases += 1;
            }
            (Err(clean), Err(padded)) => assert_eq!(
                clean.to_string(),
                padded.to_string(),
                "{label}: script data errors differ"
            ),
            _ => panic!("{label}: whitespace flipped the script-data verdict"),
        }
    }

    // A corpus that rejected everything would make the assertions vacuous.
    assert!(
        budget_cases >= 50 && script_data_cases >= 50,
        "only {budget_cases} budget and {script_data_cases} script-data successes"
    );
}
