//! Live Ogmios wire-compatibility checks.
//!
//! Every other test in this crate drives `simulate.rs` against in-process
//! fakes, which proves the parsing but not that the parsing matches what a
//! real Koios/Ogmios build sends. The Python suite has the same blind spot.
//! These tests close it against the public endpoints.
//!
//! They are OFF by default because they need the network and because a public
//! endpoint's availability is not this crate's correctness. Enable with:
//!
//! ```sh
//! COLLATERAL_LIVE_UPSTREAM=1 cargo test --test live_upstream -- --nocapture
//! ```
//!
//! Skipped tests still report `ok` — libtest has no third outcome — and the
//! reason only reaches you under `--nocapture`. Treat a green line here as
//! proof of nothing unless you saw the output.

use std::sync::Arc;

use collateral_provider::config::EnvironmentConfig;
use collateral_provider::metrics::Metrics;
use collateral_provider::script_integrity::verify_script_data_hash;
use collateral_provider::simulate::Upstream;

fn enabled() -> bool {
    match std::env::var("COLLATERAL_LIVE_UPSTREAM") {
        Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => true,
        _ => {
            eprintln!(
                "skipped: set COLLATERAL_LIVE_UPSTREAM=1 to run live upstream checks against Koios"
            );
            false
        }
    }
}

fn upstream() -> Upstream {
    let metrics = Arc::new(Metrics::new().expect("metrics registry"));
    Upstream::new(4, metrics).expect("upstream client")
}

fn env_config(koios_url: &str) -> EnvironmentConfig {
    EnvironmentConfig {
        network: "--testnet-magic 1".to_string(),
        txid: "00".repeat(32),
        txidx: 0,
        koios_url: koios_url.to_string(),
    }
}

const PREPROD: &str = "https://preprod.koios.rest/api/v1/ogmios";
const MAINNET: &str = "https://api.koios.rest/api/v1/ogmios";

/// The cost models are a funds-at-risk dependency: they feed the language
/// views that the script-data hash commits to, so a schema drift here would
/// silently reject every script transaction.
#[tokio::test]
async fn protocol_cost_models_parse_from_the_real_endpoint() {
    if !enabled() {
        return;
    }
    for (name, url) in [("preprod", PREPROD), ("mainnet", MAINNET)] {
        let models = upstream()
            .get_protocol_cost_models(name, &env_config(url))
            .await
            .unwrap_or_else(|err| panic!("{name}: live cost models unavailable: {err}"));

        assert!(!models.is_empty(), "{name}: no cost models returned");
        for (language, costs) in &models {
            assert!(*language <= 3, "{name}: unknown Plutus language {language}");
            assert!(
                !costs.is_empty(),
                "{name}: language {language} has an empty cost model"
            );
        }
        // PlutusV1 and V2 have been live since Alonzo/Vasil; their absence
        // would mean we parsed a response we do not actually understand.
        assert!(
            models.contains_key(&0) && models.contains_key(&1),
            "{name}: expected PlutusV1 and V2, got languages {:?}",
            models.keys().collect::<Vec<_>>()
        );
        eprintln!(
            "{name}: languages {:?}, parameter counts {:?}",
            models.keys().collect::<Vec<_>>(),
            models.values().map(Vec::len).collect::<Vec<_>>()
        );
    }
}

/// Detect cost-model drift away from the frozen `script_data_live.json`
/// fixture.
///
/// That fixture is what actually pins the language-view encoder (see
/// `tests/script_data_live.rs`); it pairs transactions with the cost models of
/// their own epoch, so it stays valid forever. This test answers a different
/// question: are those models still the network's current ones?
///
/// A parameter update makes the two diverge, which is expected and harmless —
/// the fixture is a historical capture, not a claim about today. But it does
/// mean the fixture no longer exercises the encoder against *current* mainnet
/// behaviour, so this reports the drift rather than failing on it. Only a
/// change in the language *set* is treated as actionable, because a new Plutus
/// version is the one drift that needs code.
#[tokio::test]
async fn frozen_cost_models_are_still_current() {
    if !enabled() {
        return;
    }
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/script_data_live.json"
    ))
    .expect("fixture readable");
    let fixture: serde_json::Value = serde_json::from_str(&raw).expect("fixture parses");
    let frozen = fixture["cost_models"]
        .as_object()
        .expect("cost_models object");

    let live = upstream()
        .get_protocol_cost_models("mainnet", &env_config(MAINNET))
        .await
        .expect("live cost models");

    let frozen_languages: Vec<u8> = frozen
        .keys()
        .map(|key| key.parse().expect("numeric language id"))
        .collect();
    let live_languages: Vec<u8> = live.keys().copied().collect();
    assert_eq!(
        frozen_languages, live_languages,
        "the network's Plutus language set changed; script_data_live.json needs re-capturing \
         and simulate::parse_protocol_cost_models may need a new language mapping"
    );

    for (language, live_costs) in &live {
        let frozen_costs: Vec<i64> = frozen[&language.to_string()]
            .as_array()
            .expect("frozen model is an array")
            .iter()
            .map(|cost| cost.as_i64().expect("cost fits i64"))
            .collect();
        if &frozen_costs == live_costs {
            eprintln!("language {language}: cost model unchanged since capture");
        } else {
            eprintln!(
                "language {language}: cost model has drifted since capture \
                 ({} vs {} parameters) — expected after a protocol update; \
                 re-capture the fixture to keep testing against current mainnet",
                frozen_costs.len(),
                live_costs.len()
            );
        }
    }

    // Sanity: the live models must at least be usable by the encoder.
    let sample = fixture["transactions"][0]["cbor"]
        .as_str()
        .expect("a transaction");
    verify_script_data_hash(sample, &live).expect("live models are well-formed enough to encode");
}

/// Prove the evaluator's JSON-RPC envelope is the one `simulate.rs` expects.
/// The transaction's inputs are long spent, so the verdict itself is
/// uninteresting — what matters is that the response parses as either a real
/// verdict or a well-formed error, never as a transport-level surprise.
#[tokio::test]
async fn evaluate_transaction_speaks_the_expected_envelope() {
    if !enabled() {
        return;
    }
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/chain_corpus.json"
    ))
    .expect("corpus readable");
    let corpus: serde_json::Value = serde_json::from_str(&raw).expect("corpus parses");
    let cbor = corpus["transactions"]
        .as_array()
        .expect("transactions")
        .iter()
        .find(|entry| entry["network"].as_str() == Some("mainnet"))
        .and_then(|entry| entry["cbor"].as_str())
        .expect("a mainnet transaction");

    let response = upstream()
        .evaluate_transaction(cbor, "mainnet", &env_config(MAINNET))
        .await
        .expect("evaluator reachable and speaking JSON-RPC");

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["method"], "evaluateTransaction");
    let has_result = response.get("result").is_some();
    let has_error = response.get("error").is_some();
    assert!(
        has_result ^ has_error,
        "response carried neither or both of result/error: {response}"
    );
    eprintln!(
        "evaluateTransaction returned {}",
        if has_result { "a result" } else { "an error" }
    );
    if let Some(error) = response.get("error") {
        // The reserved JSON-RPC band is a protocol fault, not a verdict on the
        // transaction; seeing one here would mean the endpoint does not
        // implement the method we depend on.
        let code = error.get("code").and_then(serde_json::Value::as_i64);
        assert!(
            !matches!(code, Some(code) if (-32768..=-32000).contains(&code)),
            "endpoint reported a JSON-RPC protocol fault: {error}"
        );
    }
}
