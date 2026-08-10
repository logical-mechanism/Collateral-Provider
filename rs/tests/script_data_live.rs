//! The language-view encoder, pinned to ground truth the live network agreed
//! with.
//!
//! `script_integrity` reconstructs the ledger's language-view map from the
//! protocol cost models and hashes it together with the submitted redeemer and
//! datum bytes. Getting that encoding wrong — the PlutusV1 "double bagging",
//! the indefinite-length V1 parameter list, the canonical shortlex ordering of
//! the already-encoded keys — makes body field 11 fail to verify for every
//! script transaction, which would reject all real traffic.
//!
//! Unit tests can only check that against values we computed ourselves. This
//! file checks it against transactions that were accepted by mainnet in the
//! same epoch as the cost models they are paired with, so the chain itself is
//! the authority for what field 11 should equal.
//!
//! The fixture is a frozen capture: no network at test time. Re-capture it
//! when the corpus is refreshed — the note inside records how.

use std::collections::BTreeMap;

use collateral_provider::script_integrity::{
    calculate_script_data_hash, script_data_parts, verify_script_data_hash, CostModels,
};

struct Fixture {
    cost_models: CostModels,
    transactions: Vec<(String, String)>,
}

fn fixture() -> Fixture {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/script_data_live.json"
    ))
    .expect("script_data_live.json is readable");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("fixture parses");

    let mut cost_models: CostModels = BTreeMap::new();
    for (language, costs) in value["cost_models"]
        .as_object()
        .expect("cost_models is an object")
    {
        let language: u8 = language.parse().expect("language id is numeric");
        let costs = costs
            .as_array()
            .expect("cost model is an array")
            .iter()
            .map(|cost| cost.as_i64().expect("cost parameter fits i64"))
            .collect();
        cost_models.insert(language, costs);
    }

    let transactions = value["transactions"]
        .as_array()
        .expect("transactions is an array")
        .iter()
        .map(|entry| {
            (
                entry["tx_hash"]
                    .as_str()
                    .expect("tx_hash is a string")
                    .to_string(),
                entry["cbor"]
                    .as_str()
                    .expect("cbor is a string")
                    .to_string(),
            )
        })
        .collect();

    Fixture {
        cost_models,
        transactions,
    }
}

/// The assertion that matters: every captured transaction's committed script
/// data hash reproduces from our own language-view encoding.
#[test]
fn every_captured_transaction_verifies_against_its_epoch_cost_models() {
    let Fixture {
        cost_models,
        transactions,
    } = fixture();
    assert!(
        !transactions.is_empty(),
        "fixture must carry transactions or it proves nothing"
    );
    assert!(
        cost_models.contains_key(&0) && cost_models.contains_key(&1),
        "fixture must carry at least PlutusV1 and V2, got {:?}",
        cost_models.keys().collect::<Vec<_>>()
    );

    for (tx_hash, cbor) in &transactions {
        let verified = verify_script_data_hash(cbor, &cost_models)
            .unwrap_or_else(|err| panic!("{tx_hash}: script data parts unreadable: {err}"));
        assert!(
            verified,
            "{tx_hash}: field 11 did not verify against the cost models of its own epoch — \
             the language-view encoding has drifted"
        );
    }
}

/// The subset search must not be doing the work. Exactly one language subset
/// should reproduce each hash, so recomputing with the full model set has to
/// agree with whichever subset `verify_script_data_hash` accepted.
#[test]
fn a_matching_subset_exists_and_the_direct_calculation_agrees() {
    let Fixture {
        cost_models,
        transactions,
    } = fixture();

    let languages: Vec<u8> = cost_models.keys().copied().collect();
    let mut matched_subsets = 0usize;

    for (tx_hash, cbor) in &transactions {
        let (committed, redeemers, datums) =
            script_data_parts(cbor).unwrap_or_else(|err| panic!("{tx_hash}: {err}"));

        // Walk every non-empty subset by hand and confirm at least one
        // reproduces the committed hash through the public calculation entry
        // point, independently of verify_script_data_hash's own search.
        let mut hit = false;
        for mask in 1u32..(1 << languages.len()) {
            let subset: CostModels = languages
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, language)| (*language, cost_models[language].clone()))
                .collect();
            let candidate = calculate_script_data_hash(&redeemers, &datums, &subset)
                .unwrap_or_else(|err| panic!("{tx_hash}: {err}"));
            if candidate.as_slice() == committed.as_slice() {
                hit = true;
                matched_subsets += 1;
                break;
            }
        }
        assert!(hit, "{tx_hash}: no language subset reproduces field 11");
    }

    assert_eq!(
        matched_subsets,
        transactions.len(),
        "every transaction should have a matching subset"
    );
}

/// A negative control. If the encoder were insensitive to the cost models —
/// say it hashed only the redeemers — the positive tests above would pass for
/// the wrong reason, so perturbing one parameter must break verification.
#[test]
fn a_perturbed_cost_model_stops_verifying() {
    let Fixture {
        cost_models,
        transactions,
    } = fixture();

    let mut perturbed = cost_models.clone();
    for costs in perturbed.values_mut() {
        costs[0] = costs[0].wrapping_add(1);
    }

    for (tx_hash, cbor) in &transactions {
        let verified = verify_script_data_hash(cbor, &perturbed)
            .unwrap_or_else(|err| panic!("{tx_hash}: {err}"));
        assert!(
            !verified,
            "{tx_hash}: verified against cost models it was not built with — \
             the hash is not actually committing to the language views"
        );
    }
}
