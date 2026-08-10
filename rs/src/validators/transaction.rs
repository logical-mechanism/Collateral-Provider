//! Script-data binding and phase-2 evaluation.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value as Json;

use crate::cbor::{decode_one, Value};
use crate::config::EnvironmentConfig;
use crate::error::{ApiError, ApiResult};
use crate::script_integrity::verify_script_data_hash;
use crate::simulate::Upstream;
use crate::tx_fields::{TX_WITNESS_SET, WITNESS_REDEEMERS};

/// A redeemer pointer: `(purpose tag, index)`.
pub type RedeemerPointer = (u8, u64);
/// Execution units: `(memory, cpu)`.
pub type ExecutionUnits = (u64, u64);

/// Ogmios purpose names to ledger redeemer tags. Ogmios has used both the
/// ledger-facing and client-facing names for certificate scripts across API
/// generations, so both map to 2.
pub const PURPOSE_TAGS: &[(&str, u8)] = &[
    ("spend", 0),
    ("mint", 1),
    ("publish", 2),
    ("certificate", 2),
    ("withdraw", 3),
    ("withdrawal", 3),
    ("vote", 4),
    ("propose", 5),
    ("guard", 6),
];

/// JSON-RPC reserves this inclusive range for protocol-level faults; every
/// other code is a domain verdict from Ogmios itself.
const JSONRPC_RESERVED: std::ops::RangeInclusive<i64> = -32768..=-32000;

/// The flat pointer form. Anchored at both ends, so it is a full match in the
/// same sense as Python's `re.fullmatch`.
static VALIDATOR_POINTER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(spend|mint|publish|certificate|withdraw|withdrawal|vote|propose|guard):([0-9]{1,20})$",
    )
    .expect("the pointer pattern is a compile-time constant")
});

/// Resolve the redeemer pointer from either shape Ogmios ships.
///
/// Ogmios names the validator a budget belongs to in two different ways
/// across its v6 line: the structured `{"index": 0, "purpose": "mint"}` that
/// Koios's build returns, and the flat `"mint:0"` string used by later
/// releases. Accepting only the string turned every transaction that
/// genuinely passed evaluation into a 503, because the result was read as
/// malformed. Returns `None` when the pointer is neither shape.
pub fn validator_pointer(validator: &Json) -> Option<RedeemerPointer> {
    if let Some(text) = validator.as_str() {
        let captures = VALIDATOR_POINTER_RE.captures(text)?;
        let tag = purpose_tag(captures.get(1)?.as_str())?;
        // Twenty digits overflow a u64. Python keeps the big integer and lets
        // the caller's range check reject it; failing here reaches the same
        // 503 by the same reasoning.
        let index = captures.get(2)?.as_str().parse::<u64>().ok()?;
        return Some((tag, index));
    }
    if let Some(object) = validator.as_object() {
        let tag = purpose_tag(object.get("purpose")?.as_str()?)?;
        // `as_u64` is false for booleans, negatives and floats, which is what
        // Python's `isinstance(x, int) and not isinstance(x, bool)` means.
        let index = object.get("index")?.as_u64()?;
        return Some((tag, index));
    }
    None
}

/// Extract execution units committed by the submitted witness set.
///
/// `evaluateTransaction` estimates what each script needs; it does not prove
/// the execution units already encoded in the transaction are large enough.
/// The script-integrity hash in the signed body binds these redeemers, so
/// comparing the committed budgets to the estimate closes the otherwise
/// straightforward phase-2 out-of-budget path.
///
/// Both the Alonzo/Babbage list encoding and the Conway map encoding are
/// accepted. Everything else fails locally before an upstream call.
pub fn committed_redeemer_budgets(
    tx_cbor: &str,
) -> ApiResult<BTreeMap<RedeemerPointer, ExecutionUnits>> {
    let bytes =
        hex::decode(tx_cbor).map_err(|_| ApiError::validation("Invalid CBOR Data In Tx"))?;
    // `cbor2.loads` decodes one value and ignores whatever follows it;
    // rejecting trailing bytes is `validators::cbor::check_tx_body`'s job and
    // it has already run by the time a request reaches here.
    let (transaction, _) =
        decode_one(&bytes).map_err(|_| ApiError::validation("Invalid CBOR Data In Tx"))?;

    let items = transaction
        .as_array()
        .filter(|items| items.len() == 4)
        .ok_or_else(|| ApiError::validation("Tx Must Have Four Elements"))?;
    let witness_set = &items[TX_WITNESS_SET];
    if witness_set.as_map().is_none() {
        return Err(ApiError::validation("Witness Set Is Not A Dict"));
    }
    // `dict.get` cannot tell an absent key from one explicitly set to null,
    // and both mean the same thing here.
    let redeemers = match witness_set.map_get(WITNESS_REDEEMERS) {
        Some(redeemers) if !matches!(redeemers, Value::Null) => redeemers,
        _ => return Err(ApiError::validation("Transaction Has No Redeemers")),
    };

    // A CBOR map decodes to a Python dict, where a repeated key silently
    // overwrites the earlier entry — so a duplicate pointer is only reachable
    // through the list encoding, and only there is it an error. Reproducing
    // both halves keeps this port from rejecting a transaction the running
    // service accepts.
    let mut duplicates_are_errors = false;
    let entries: Vec<(&Value, &Value, &Value)> = match redeemers {
        Value::Map(items) => {
            let mut entries = Vec::with_capacity(items.len());
            for (key, value) in items {
                let pointer = key
                    .as_array()
                    .filter(|pointer| pointer.len() == 2)
                    .ok_or_else(|| ApiError::validation("Redeemer Pointer Is Invalid"))?;
                let fields = value
                    .as_array()
                    .filter(|fields| fields.len() == 2)
                    .ok_or_else(|| ApiError::validation("Redeemer Value Is Invalid"))?;
                entries.push((&pointer[0], &pointer[1], &fields[1]));
            }
            entries
        }
        Value::Array(items) => {
            duplicates_are_errors = true;
            let mut entries = Vec::with_capacity(items.len());
            for value in items {
                let fields = value
                    .as_array()
                    .filter(|fields| fields.len() == 4)
                    .ok_or_else(|| ApiError::validation("Redeemer Value Is Invalid"))?;
                entries.push((&fields[0], &fields[1], &fields[3]));
            }
            entries
        }
        _ => return Err(ApiError::validation("Redeemers Are Not A Map Or List")),
    };

    if entries.is_empty() {
        return Err(ApiError::validation("Transaction Has No Redeemers"));
    }
    let mut budgets = BTreeMap::new();
    for (tag, index, execution_units) in entries {
        let pointer = redeemer_pointer(tag, index)?;
        if duplicates_are_errors && budgets.contains_key(&pointer) {
            return Err(ApiError::validation("Redeemer Pointer Is Duplicated"));
        }
        budgets.insert(pointer, execution_units_of(execution_units)?);
    }
    Ok(budgets)
}

/// Run the script-integrity and phase-2 evaluation checks.
///
/// A non-empty, well-formed result proves the supplied Plutus context
/// evaluated successfully at that upstream. It is not full phase-1 ledger
/// validation or a balance check. Network/upstream failures surface as 503
/// instead of being misreported as a bad-tx 400.
pub async fn check_valid_tx(
    tx_body_cbor: &str,
    environment: &str,
    env_config: &EnvironmentConfig,
    upstream: &Upstream,
) -> ApiResult<()> {
    // Local, free, and decisive: a transaction whose redeemers we cannot read
    // never reaches an upstream slot.
    let committed_budgets = committed_redeemer_budgets(tx_body_cbor)?;

    let cost_models = upstream
        .get_protocol_cost_models(environment, env_config)
        .await
        .map_err(|err| {
            tracing::error!(target: "api", "Protocol Parameters Unavailable: {}", err);
            ApiError::Upstream
        })?;

    match verify_script_data_hash(tx_body_cbor, &cost_models) {
        Err(err) => {
            // The internal message names cursor mechanics ("truncated CBOR",
            // "transaction map key is duplicated"), which is operator
            // vocabulary, not caller vocabulary. Log it, and keep the
            // wallet-facing string in the repo's Title Case convention.
            tracing::warn!(
                target: "api",
                "Script data hash could not be established: {}",
                err
            );
            return Err(ApiError::validation("Invalid Script Data Hash In Tx"));
        }
        Ok(false) => {
            return Err(ApiError::validation(
                "Script Data Hash Does Not Commit To Submitted Redeemers And Datums",
            ));
        }
        Ok(true) => {}
    }

    let response = upstream
        .evaluate_transaction(tx_body_cbor, environment, env_config)
        .await
        .map_err(|err| {
            tracing::error!(target: "api", "Upstream Evaluation Unavailable: {}", err);
            ApiError::Upstream
        })?;

    check_evaluation(&response, &committed_budgets)
}

/// Hold the upstream verdict against the budgets the transaction committed.
fn check_evaluation(
    response: &Json,
    committed_budgets: &BTreeMap<RedeemerPointer, ExecutionUnits>,
) -> ApiResult<()> {
    let evaluations = evaluation_results(response)?;
    if evaluations.is_empty() {
        return Err(ApiError::validation(
            "Transaction Has No Plutus Scripts To Evaluate",
        ));
    }
    let Some(evaluated_budgets) = evaluated_redeemer_budgets(evaluations) else {
        tracing::error!(target: "api", "Malformed Upstream Evaluation Result");
        return Err(ApiError::Upstream);
    };
    if !evaluated_budgets.keys().eq(committed_budgets.keys()) {
        tracing::error!(
            target: "api",
            "Upstream Evaluation Redeemer Pointers Do Not Match Transaction"
        );
        return Err(ApiError::Upstream);
    }
    for (pointer, required) in &evaluated_budgets {
        // Absent keys were ruled out by the set comparison above.
        let committed = committed_budgets.get(pointer).copied().unwrap_or_default();
        if committed.0 < required.0 || committed.1 < required.1 {
            return Err(ApiError::validation(
                "Redeemer Execution Budget Is Too Small",
            ));
        }
    }
    Ok(())
}

/// Unwrap the JSON-RPC envelope into the list of evaluation results.
fn evaluation_results(response: &Json) -> ApiResult<&[Json]> {
    if response.is_object() && response.get("error").is_some() && response.get("result").is_none() {
        // Distinguish "the ledger rejected this transaction" from "we asked
        // the evaluator the wrong question". JSON-RPC reserves
        // -32768..-32000 for protocol-level faults: a KOIOS_URL pointing at a
        // build without evaluateTransaction answers -32601 Method Not Found
        // over HTTP 200, and reporting that as a 400 tells every wallet its
        // transaction is bad while the service is the broken party. Ogmios's
        // own domain errors sit outside that range and are real verdicts.
        let error = &response["error"];
        let code = error
            .as_object()
            .and_then(|error| error.get("code"))
            .and_then(Json::as_i64);
        return match code {
            Some(code) if !JSONRPC_RESERVED.contains(&code) => {
                Err(ApiError::validation("Transaction Fails Validation"))
            }
            _ => {
                tracing::error!(
                    target: "api",
                    "Upstream Evaluation Rejected The Request: {}",
                    error
                );
                Err(ApiError::Upstream)
            }
        };
    }

    let results = response.get("result").and_then(Json::as_array);
    let well_formed = response.get("jsonrpc").and_then(Json::as_str) == Some("2.0")
        && results.is_some()
        && response.get("error").is_none()
        && response.get("method").and_then(Json::as_str) == Some("evaluateTransaction");
    match results.filter(|_| well_formed) {
        Some(results) => Ok(results),
        None => {
            tracing::error!(target: "api", "Malformed Upstream Evaluation Response");
            Err(ApiError::Upstream)
        }
    }
}

/// Collect the evaluated requirements, or `None` if any entry is unusable.
fn evaluated_redeemer_budgets(
    evaluations: &[Json],
) -> Option<BTreeMap<RedeemerPointer, ExecutionUnits>> {
    let mut budgets = BTreeMap::new();
    for evaluation in evaluations {
        let (pointer, budget) = evaluation_result(evaluation)?;
        // Two budgets for one pointer means we cannot tell which one the
        // evaluator actually meant.
        if budgets.insert(pointer, budget).is_some() {
            return None;
        }
    }
    Some(budgets)
}

/// Validate one evaluation entry into `(pointer, required units)`.
fn evaluation_result(evaluation: &Json) -> Option<(RedeemerPointer, ExecutionUnits)> {
    let entry = evaluation.as_object()?;
    let pointer = validator_pointer(entry.get("validator")?)?;
    let budget = entry.get("budget")?.as_object()?;
    let memory = positive_budget(budget.get("memory"))?;
    let cpu = positive_budget(budget.get("cpu"))?;
    Some((pointer, (memory, cpu)))
}

/// A real evaluation is never free: running a script starts the CEK machine,
/// which charges its startup cost before executing a single term, so every
/// genuine budget is strictly positive. A zero is therefore proof the
/// evaluator did not evaluate anything — and it is the cheapest possible lie,
/// because `committed >= 0` holds for every transaction, which would let an
/// evaluator wave through arbitrarily under-budgeted redeemers. Those fail
/// phase 2 on chain and consume the collateral.
///
/// This only closes the laziest forgery; an evaluator returning 1 or a
/// plausible-looking underestimate is not detectable from here. The real
/// defence against a dishonest evaluator is running one you trust (see
/// SECURITY.md), not this check.
fn positive_budget(amount: Option<&Json>) -> Option<u64> {
    amount.and_then(Json::as_u64).filter(|amount| *amount > 0)
}

/// The purpose tag for an Ogmios purpose name.
fn purpose_tag(name: &str) -> Option<u8> {
    PURPOSE_TAGS
        .iter()
        .find(|(purpose, _)| *purpose == name)
        .map(|(_, tag)| *tag)
}

/// A committed redeemer's `(tag, index)`, both range-checked.
fn redeemer_pointer(tag: &Value, index: &Value) -> ApiResult<RedeemerPointer> {
    let tag = tag
        .as_u64()
        .and_then(|tag| {
            PURPOSE_TAGS
                .iter()
                .map(|(_, known)| *known)
                .find(|known| u64::from(*known) == tag)
        })
        .ok_or_else(|| ApiError::validation("Redeemer Purpose Is Invalid"))?;
    let index = index
        .as_u64()
        .ok_or_else(|| ApiError::validation("Redeemer Index Is Invalid"))?;
    Ok((tag, index))
}

/// The `[memory, cpu]` pair a redeemer commits to.
fn execution_units_of(value: &Value) -> ApiResult<ExecutionUnits> {
    let invalid = || ApiError::validation("Redeemer Execution Units Are Invalid");
    let units = value
        .as_array()
        .filter(|units| units.len() == 2)
        .ok_or_else(invalid)?;
    let memory = units[0].as_u64().ok_or_else(invalid)?;
    let cpu = units[1].as_u64().ok_or_else(invalid)?;
    Ok((memory, cpu))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `[{}, {5: {[0, 0]: [d87980, [10, 10]]}}, true, null]` — the Conway map
    /// encoding, cross-checked against `cbor2.dumps` in the Python suite.
    const CONWAY_TX: &str = "84a0a105a182000082d87980820a0af5f6";
    /// The same redeemer in the Alonzo/Babbage list encoding.
    const LEGACY_TX: &str = "84a0a10581840000d87980820a0af5f6";

    fn detail<T>(result: ApiResult<T>) -> String {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(err) => err.detail().to_string(),
        }
    }

    fn is_upstream<T>(result: ApiResult<T>) -> bool {
        matches!(result, Err(ApiError::Upstream))
    }

    fn budgets(tx: &str) -> BTreeMap<RedeemerPointer, ExecutionUnits> {
        committed_redeemer_budgets(tx).expect("fixture parses")
    }

    fn response(evaluations: Json) -> Json {
        json!({
            "jsonrpc": "2.0",
            "method": "evaluateTransaction",
            "result": evaluations,
        })
    }

    // --- validator_pointer -------------------------------------------------

    #[test]
    fn flat_pointer_covers_every_purpose_name() {
        for (purpose, tag) in PURPOSE_TAGS {
            let pointer = validator_pointer(&json!(format!("{purpose}:7")));
            assert_eq!(pointer, Some((*tag, 7)), "{purpose}");
        }
    }

    #[test]
    fn flat_pointer_accepts_leading_zeros_and_wide_indexes() {
        assert_eq!(validator_pointer(&json!("spend:00")), Some((0, 0)));
        assert_eq!(
            validator_pointer(&json!("mint:18446744073709551615")),
            Some((1, u64::MAX))
        );
    }

    #[test]
    fn flat_pointer_rejects_anything_the_regex_does_not_fully_match() {
        for text in [
            "spend",
            "spend:",
            ":0",
            "spend:0 ",
            " spend:0",
            "spend:0\n",
            "Spend:0",
            "spend:0:1",
            "spend::0",
            "spend:-1",
            "spend:0x1",
            "nonsense:0",
            // Twenty digits still parse as a pointer in Python, then fail its
            // range check; either way it is malformed, not a verdict.
            "spend:99999999999999999999",
            // Twenty-one digits do not even match the pattern.
            "spend:000000000000000000000",
        ] {
            assert_eq!(validator_pointer(&json!(text)), None, "{text}");
        }
    }

    #[test]
    fn structured_pointer_is_the_shape_koios_returns() {
        assert_eq!(
            validator_pointer(&json!({"index": 0, "purpose": "spend"})),
            Some((0, 0))
        );
        assert_eq!(
            validator_pointer(&json!({"index": 4, "purpose": "certificate"})),
            Some((2, 4))
        );
    }

    #[test]
    fn structured_pointer_rejects_every_malformed_variant() {
        for validator in [
            json!({"index": 0}),
            json!({"purpose": "spend"}),
            json!({"index": -1, "purpose": "spend"}),
            json!({"index": true, "purpose": "spend"}),
            json!({"index": 0.5, "purpose": "spend"}),
            json!({"index": 0, "purpose": "nonsense"}),
            json!({"index": "0", "purpose": "spend"}),
            json!({"index": 0, "purpose": 1}),
        ] {
            assert_eq!(validator_pointer(&validator), None, "{validator}");
        }
    }

    #[test]
    fn pointer_of_any_other_json_type_is_none() {
        for validator in [json!(null), json!(0), json!(true), json!(["spend", 0])] {
            assert_eq!(validator_pointer(&validator), None, "{validator}");
        }
    }

    // --- committed_redeemer_budgets ----------------------------------------

    #[test]
    fn both_redeemer_encodings_yield_the_same_budgets() {
        let expected: BTreeMap<RedeemerPointer, ExecutionUnits> = [((0, 0), (10, 10))].into();
        assert_eq!(budgets(CONWAY_TX), expected);
        assert_eq!(budgets(LEGACY_TX), expected);
    }

    #[test]
    fn several_redeemers_are_all_collected() {
        // {[0,0]: .. [10,10], [1,3]: .. [7,8]}
        let tx = "84a0a105a282000082d87980820a0a82010382d87980820708f5f6";
        let expected: BTreeMap<RedeemerPointer, ExecutionUnits> =
            [((0, 0), (10, 10)), ((1, 3), (7, 8))].into();
        assert_eq!(budgets(tx), expected);
    }

    #[test]
    fn u64_boundaries_on_committed_units() {
        // [0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff] is the largest pair.
        let max = "84a0a105a182000082d87980821bffffffffffffffff1bfffffffffffffffff5f6";
        assert_eq!(budgets(max), [((0, 0), (u64::MAX, u64::MAX))].into());
        // 2^64 arrives as a bignum and is out of range.
        let over = "84a0a105a182000082d8798082c24901000000000000000001f5f6";
        assert_eq!(
            detail(committed_redeemer_budgets(over)),
            "Redeemer Execution Units Are Invalid"
        );
    }

    #[test]
    fn envelope_failures_report_their_own_messages() {
        for (tx, expected) in [
            ("zz", "Invalid CBOR Data In Tx"),
            ("abc", "Invalid CBOR Data In Tx"),
            ("", "Invalid CBOR Data In Tx"),
            // [{}, {}, true] — three elements.
            ("83a0a0f5", "Tx Must Have Four Elements"),
            ("a10102", "Tx Must Have Four Elements"),
            // [{}, [], true, null] — witness set is a list.
            ("84a080f5f6", "Witness Set Is Not A Dict"),
        ] {
            assert_eq!(detail(committed_redeemer_budgets(tx)), expected, "{tx}");
        }
    }

    #[test]
    fn trailing_bytes_are_ignored_exactly_as_cbor2_loads_does() {
        let trailing = format!("{CONWAY_TX}00");
        assert_eq!(budgets(&trailing), [((0, 0), (10, 10))].into());
    }

    #[test]
    fn missing_or_empty_redeemers_short_circuit_before_any_upstream_call() {
        for tx in [
            // [{}, {}, true, null]
            "84a0a0f5f6",
            // key 5 present but null
            "84a0a105f6f5f6",
            // empty map
            "84a0a105a0f5f6",
            // empty list
            "84a0a10580f5f6",
        ] {
            assert_eq!(
                detail(committed_redeemer_budgets(tx)),
                "Transaction Has No Redeemers",
                "{tx}"
            );
        }
    }

    #[test]
    fn structural_redeemer_failures_report_their_own_messages() {
        for (tx, expected) in [
            // key is a one-element array
            (
                "84a0a105a1810082d87980820a0af5f6",
                "Redeemer Pointer Is Invalid",
            ),
            // value is a one-element array
            ("84a0a105a182000081d87980f5f6", "Redeemer Value Is Invalid"),
            // legacy entry with three elements
            ("84a0a10581830000d87980f5f6", "Redeemer Value Is Invalid"),
            // redeemers are a text string
            ("84a0a105646e6f7065f5f6", "Redeemers Are Not A Map Or List"),
        ] {
            assert_eq!(detail(committed_redeemer_budgets(tx)), expected, "{tx}");
        }
    }

    #[test]
    fn pointer_components_are_range_and_type_checked() {
        for (tx, expected) in [
            // tag 7 is not a purpose
            (
                "84a0a105a182070082d87980820a0af5f6",
                "Redeemer Purpose Is Invalid",
            ),
            // tag -1
            (
                "84a0a105a182200082d87980820a0af5f6",
                "Redeemer Purpose Is Invalid",
            ),
            // tag true — a CBOR boolean is never an integer
            (
                "84a0a105a182f50082d87980820a0af5f6",
                "Redeemer Purpose Is Invalid",
            ),
            // index -1
            (
                "84a0a105a182002082d87980820a0af5f6",
                "Redeemer Index Is Invalid",
            ),
        ] {
            assert_eq!(detail(committed_redeemer_budgets(tx)), expected, "{tx}");
        }
        // tag 6 (guard) is the highest accepted purpose.
        assert_eq!(
            budgets("84a0a105a182060082d87980820a0af5f6"),
            [((6, 0), (10, 10))].into()
        );
    }

    #[test]
    fn execution_units_must_be_a_pair_of_uints() {
        for tx in [
            // [10]
            "84a0a105a182000082d87980810af5f6",
            // [-1, 10]
            "84a0a105a182000082d8798082200af5f6",
            // 10 — not a list at all
            "84a0a105a182000082d879800af5f6",
        ] {
            assert_eq!(
                detail(committed_redeemer_budgets(tx)),
                "Redeemer Execution Units Are Invalid",
                "{tx}"
            );
        }
    }

    #[test]
    fn duplicate_pointers_follow_the_encoding_they_arrived_in() {
        // The list encoding can genuinely repeat a pointer, and does not.
        let legacy = "84a0a10582840000d87980820a0a840000d87980820b0bf5f6";
        assert_eq!(
            detail(committed_redeemer_budgets(legacy)),
            "Redeemer Pointer Is Duplicated"
        );
        // A repeated map key collapses last-wins in Python's decoder, so the
        // second entry simply wins here too.
        let conway = "84a0a105a282000082d87980820a0a82000082d87980820b0bf5f6";
        assert_eq!(budgets(conway), [((0, 0), (11, 11))].into());
    }

    // --- evaluation results ------------------------------------------------

    #[test]
    fn a_correlated_result_passes_silently() {
        let response =
            response(json!([{"validator": "spend:0", "budget": {"memory": 1, "cpu": 1}}]));
        assert!(check_evaluation(&response, &budgets(CONWAY_TX)).is_ok());
    }

    #[test]
    fn the_structured_pointer_is_held_to_the_same_budget_comparison() {
        let response = response(
            json!([{"validator": {"index": 0, "purpose": "spend"}, "budget": {"memory": 11, "cpu": 1}}]),
        );
        assert_eq!(
            detail(check_evaluation(&response, &budgets(CONWAY_TX))),
            "Redeemer Execution Budget Is Too Small"
        );
    }

    #[test]
    fn committed_units_must_meet_the_requirement_on_both_axes() {
        for budget in [
            json!({"memory": 10, "cpu": 10}),
            json!({"memory": 1, "cpu": 10}),
        ] {
            let response = response(json!([{"validator": "spend:0", "budget": budget}]));
            assert!(check_evaluation(&response, &budgets(CONWAY_TX)).is_ok());
        }
        for budget in [
            json!({"memory": 11, "cpu": 10}),
            json!({"memory": 10, "cpu": 11}),
        ] {
            let response = response(json!([{"validator": "spend:0", "budget": budget}]));
            assert_eq!(
                detail(check_evaluation(&response, &budgets(CONWAY_TX))),
                "Redeemer Execution Budget Is Too Small"
            );
        }
    }

    #[test]
    fn a_zero_budget_is_an_upstream_failure_not_a_bad_transaction() {
        // Zero is the cheapest possible lie: `committed >= 0` is vacuous.
        for budget in [
            json!({"memory": 0, "cpu": 0}),
            json!({"memory": 0, "cpu": 500000}),
            json!({"memory": 1000, "cpu": 0}),
        ] {
            let response = response(json!([{"validator": "spend:0", "budget": budget}]));
            assert!(
                is_upstream(check_evaluation(&response, &budgets(CONWAY_TX))),
                "{budget}"
            );
        }
        // The floor is "not zero", not a guess at a realistic minimum.
        let response =
            response(json!([{"validator": "spend:0", "budget": {"memory": 1, "cpu": 1}}]));
        assert!(check_evaluation(&response, &budgets(CONWAY_TX)).is_ok());
    }

    #[test]
    fn malformed_evaluation_entries_are_upstream_failures() {
        for evaluation in [
            json!({}),
            json!({"validator": "spend:0"}),
            json!({"validator": "spend:0", "budget": {"memory": true, "cpu": 1}}),
            json!({"validator": "spend:0", "budget": {"memory": -1, "cpu": 1}}),
            json!({"validator": "spend:0", "budget": [1, 1]}),
            json!("spend:0"),
        ] {
            let response = response(json!([evaluation]));
            assert!(
                is_upstream(check_evaluation(&response, &budgets(CONWAY_TX))),
                "{evaluation}"
            );
        }
    }

    #[test]
    fn an_empty_result_means_there_was_nothing_to_evaluate() {
        assert_eq!(
            detail(check_evaluation(&response(json!([])), &budgets(CONWAY_TX))),
            "Transaction Has No Plutus Scripts To Evaluate"
        );
    }

    #[test]
    fn pointers_must_match_the_committed_set_exactly() {
        // Right budget, wrong validator.
        let mismatched =
            response(json!([{"validator": "mint:0", "budget": {"memory": 1, "cpu": 1}}]));
        assert!(is_upstream(check_evaluation(
            &mismatched,
            &budgets(CONWAY_TX)
        )));
        // A superset is not a match either.
        let extra = response(json!([
            {"validator": "spend:0", "budget": {"memory": 1, "cpu": 1}},
            {"validator": "mint:0", "budget": {"memory": 1, "cpu": 1}},
        ]));
        assert!(is_upstream(check_evaluation(&extra, &budgets(CONWAY_TX))));
        // Two budgets for one pointer is unresolvable.
        let duplicated = response(json!([
            {"validator": "spend:0", "budget": {"memory": 1, "cpu": 1}},
            {"validator": "spend:0", "budget": {"memory": 2, "cpu": 2}},
        ]));
        assert!(is_upstream(check_evaluation(
            &duplicated,
            &budgets(CONWAY_TX)
        )));
    }

    // --- JSON-RPC envelope -------------------------------------------------

    #[test]
    fn an_ogmios_domain_error_is_a_real_verdict() {
        // 3161 = script went beyond its allocated budget.
        let response = json!({
            "jsonrpc": "2.0",
            "method": "evaluateTransaction",
            "error": {"code": 3161, "message": "budget exceeded"},
        });
        assert_eq!(
            detail(check_evaluation(&response, &budgets(CONWAY_TX))),
            "Transaction Fails Validation"
        );
    }

    #[test]
    fn reserved_jsonrpc_codes_are_never_the_callers_fault() {
        // -32601 is what a build without evaluateTransaction answers, over
        // HTTP 200. Calling that a 400 blames every wallet for our outage.
        for code in [-32768, -32700, -32601, -32602, -32603, -32000] {
            let response = json!({
                "jsonrpc": "2.0",
                "method": "evaluateTransaction",
                "error": {"code": code, "message": "protocol fault"},
            });
            assert!(
                is_upstream(check_evaluation(&response, &budgets(CONWAY_TX))),
                "{code}"
            );
        }
        // Just outside the reserved range in both directions is a verdict.
        for code in [-32769, -31999] {
            let response = json!({
                "jsonrpc": "2.0",
                "method": "evaluateTransaction",
                "error": {"code": code},
            });
            assert_eq!(
                detail(check_evaluation(&response, &budgets(CONWAY_TX))),
                "Transaction Fails Validation",
                "{code}"
            );
        }
    }

    #[test]
    fn an_unclassifiable_error_is_never_a_400() {
        for error in [
            json!({"message": "no code"}),
            json!("just a string"),
            json!({"code": "3161"}),
            json!({"code": true}),
            json!({"code": 3161.5}),
            json!(null),
        ] {
            let response = json!({
                "jsonrpc": "2.0",
                "method": "evaluateTransaction",
                "error": error,
            });
            assert!(
                is_upstream(check_evaluation(&response, &budgets(CONWAY_TX))),
                "{error}"
            );
        }
    }

    #[test]
    fn a_malformed_envelope_is_an_upstream_failure() {
        for response in [
            json!(null),
            json!([]),
            json!({"result": []}),
            json!({"jsonrpc": "2.0", "result": null}),
            json!({"jsonrpc": "2.0", "result": [], "error": {}}),
            json!({"jsonrpc": "2.0", "method": "submitTransaction", "result": []}),
            json!({"jsonrpc": "1.0", "method": "evaluateTransaction", "result": []}),
            json!({"jsonrpc": 2.0, "method": "evaluateTransaction", "result": []}),
            json!({"method": "evaluateTransaction", "result": []}),
        ] {
            assert!(
                is_upstream(check_evaluation(&response, &budgets(CONWAY_TX))),
                "{response}"
            );
        }
    }
}
