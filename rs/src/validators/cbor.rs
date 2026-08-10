//! Structural checks over the submitted transaction body.

use std::collections::HashSet;

use crate::ban_list::BanList;
use crate::cbor::{decode_hex, Value};
use crate::config::EnvironmentConfig;
use crate::error::{ApiError, ApiResult};
use crate::tx_fields::{
    COLLATERAL_INPUTS, COLLATERAL_RETURN, INPUTS, OUTPUTS, REQUIRED_SIGNERS, SET_TAG, TX_BODY,
    TX_IS_VALID, TX_WITNESS_SET,
};

/// Normalize a CDDL `set<T>` body field into a list of entries.
///
/// Conway permits both encodings — `set<a0> = #6.258([* a0]) / [* a0]`. Gating
/// on the tagged form alone rejects a legal encoding and breaks builders that
/// omit tag 258, so normalize the container here and let every caller work
/// against one shape.
///
/// Entries are de-duplicated so the untagged form carries the same semantics
/// as the tagged one, where Python's decoder collapses duplicates for us.
///
/// Returns `None` when the value is neither encoding.
pub fn set_items(value: &Value) -> Option<Vec<&Value>> {
    let entries = match value {
        Value::Tag(tag, inner) => {
            if *tag != SET_TAG {
                return None;
            }
            inner.as_array()?
        }
        Value::Array(items) => items.as_slice(),
        _ => return None,
    };

    // Python de-duplicates through a real hash set. A linear scan would be
    // quadratic in an attacker-chosen entry count — a 16 KiB body holds
    // thousands of one-byte entries — so hash the structure and keep the
    // original's complexity.
    let mut seen: HashSet<&Value> = HashSet::with_capacity(entries.len());
    let mut normalized = Vec::with_capacity(entries.len());
    for entry in entries {
        if seen.insert(entry) {
            normalized.push(entry);
        }
    }
    Some(normalized)
}

/// Decode the hex envelope and enforce the on-chain max tx size.
pub fn check_cbor_hex(tx_body_cbor: &str, max_tx_size: usize) -> ApiResult<Vec<u8>> {
    if tx_body_cbor.is_empty() {
        return Err(ApiError::validation("Tx Can't Be Empty"));
    }
    let Some(tx_bytes) = decode_hex(tx_body_cbor) else {
        return Err(ApiError::validation("Invalid Hex Data In Tx"));
    };
    if tx_bytes.len() > max_tx_size {
        return Err(ApiError::validation("Tx Is Too Large"));
    }
    Ok(tx_bytes)
}

/// Decode the outer CBOR envelope and return the inner body map.
///
/// Validates that the envelope is a 4-element list with no trailing data,
/// that the body and witness set are maps, and that the is_valid flag is
/// `true`. An explicit `false` would direct the chain to consume the
/// collateral, so we refuse to sign such transactions.
pub fn check_tx_body(tx_bytes: &[u8]) -> ApiResult<Value> {
    let Ok((tx, consumed)) = crate::cbor::decode_one(tx_bytes) else {
        return Err(ApiError::validation("Invalid CBOR Data In Tx"));
    };
    let Value::Array(mut items) = tx else {
        return Err(ApiError::validation("Tx Is Not A List"));
    };
    // Checked after list-ness, before length: same order as the Python cursor.
    if consumed != tx_bytes.len() {
        return Err(ApiError::validation("Trailing Data After Tx"));
    }
    if items.len() != 4 {
        return Err(ApiError::validation("Tx Must Have Four Elements"));
    }

    if items[TX_BODY].as_map().is_none() {
        return Err(ApiError::validation("Tx Body Is Not A Dict"));
    }
    if items[TX_WITNESS_SET].as_map().is_none() {
        return Err(ApiError::validation("Witness Set Is Not A Dict"));
    }
    match items[TX_IS_VALID].as_bool() {
        None => return Err(ApiError::validation("Boolean Is Not A Bool")),
        Some(false) => return Err(ApiError::validation("Boolean Can't Be False")),
        Some(true) => {}
    }

    Ok(items.swap_remove(TX_BODY))
}

/// Reject any tx whose regular inputs include the collateral UTxO — that
/// would consume it instead of just locking it as collateral.
pub fn check_inputs(body: &Value, env_config: &EnvironmentConfig) -> ApiResult<()> {
    let Some(field) = body.map_get(INPUTS) else {
        return Err(ApiError::validation("Inputs Does Not Exist In Body"));
    };
    let Some(inputs) = set_items(field) else {
        return Err(ApiError::validation("Inputs Are Not A Set"));
    };

    for utxo in inputs {
        let (txid, index) = check_utxo_shape(utxo)?;
        if is_collateral(txid, index, env_config) {
            return Err(ApiError::validation("Collateral Is Being Spent In Tx"));
        }
    }
    Ok(())
}

/// Reject txs that send funds to addresses on the manual ban list.
///
/// Index 0 works for both Shelley list-encoded outputs (where 0 is the
/// address slot) and Babbage map-encoded outputs (where 0 is the address map
/// key), so both shapes fall through the same check.
pub fn check_outputs(body: &Value, bans: &BanList) -> ApiResult<()> {
    let Some(field) = body.map_get(OUTPUTS) else {
        return Err(ApiError::validation("Outputs Does Not Exist In Body"));
    };
    let Some(outputs) = field.as_array() else {
        return Err(ApiError::validation("Outputs Are Not A List"));
    };

    for utxo in outputs {
        if !matches!(utxo, Value::Array(_) | Value::Map(_)) {
            return Err(ApiError::validation("UTxO Is Not A List Or Dict"));
        }
        // A missing slot and a wrong-typed slot are distinct failures, so the
        // operator reading the log can tell a truncated output from a
        // mis-encoded one.
        let Some(address) = utxo.index_or_key(0) else {
            return Err(ApiError::validation("TxId Does Not Exist In UTxO"));
        };
        let Some(address) = address.as_bytes() else {
            return Err(ApiError::validation("TxId Is Not Bytes"));
        };
        let address = hex::encode(address);
        if bans.is_banned_address(&address) {
            return Err(ApiError::validation(format!(
                "The Address: {address} Is Banned"
            )));
        }
    }
    Ok(())
}

/// Require that this provider's collateral UTxO is the single referenced
/// collateral input.
pub fn check_collateral(body: &Value, env_config: &EnvironmentConfig) -> ApiResult<()> {
    let Some(field) = body.map_get(COLLATERAL_INPUTS) else {
        return Err(ApiError::validation("Collateral Does Not Exist In Body"));
    };
    let Some(collaterals) = set_items(field) else {
        return Err(ApiError::validation("Collateral Is Not A Set"));
    };
    if collaterals.len() != 1 {
        return Err(ApiError::validation(
            "Exactly One Collateral Input Is Required",
        ));
    }

    for utxo in collaterals {
        let (txid, index) = check_utxo_shape(utxo)?;
        if is_collateral(txid, index, env_config) {
            return Ok(());
        }
    }
    Err(ApiError::validation("Collateral Is Not Being Used In Tx"))
}

/// If the tx sets CIP-40 collateral return, require it to pay us back.
///
/// Body field 16 is consulted by the ledger only on the phase-2-invalid
/// branch, so it cannot make a script fail and is not itself a route to
/// losing the collateral. What it decides is *who receives the remainder*
/// when the collateral is consumed. Left unchecked, an attacker names their
/// own address and keeps roughly the collateral minus the covered fee, which
/// turns a break-even griefing attack into a profitable one.
///
/// The field stays optional so builders that omit it are unaffected. When
/// present, the payment credential must be this provider's key hash.
///
/// A Shelley address is `header || payment_credential[28] || ...`. The high
/// nibble of the header selects the address type; even types carry a key-hash
/// payment credential, odd types a script hash.
pub fn check_collateral_return(body: &Value, pkh: &str) -> ApiResult<()> {
    let Some(utxo) = body.map_get(COLLATERAL_RETURN) else {
        return Ok(());
    };
    if !matches!(utxo, Value::Array(_) | Value::Map(_)) {
        return Err(ApiError::validation(
            "Collateral Return Is Not A List Or Dict",
        ));
    }
    let Some(address) = utxo.index_or_key(0) else {
        return Err(ApiError::validation("Collateral Return Has No Address"));
    };
    let Some(address) = address.as_bytes().filter(|bytes| bytes.len() >= 29) else {
        return Err(ApiError::validation(
            "Collateral Return Address Is Malformed",
        ));
    };
    if (address[0] >> 4) % 2 != 0 {
        return Err(ApiError::validation(
            "Collateral Return Must Not Pay A Script Address",
        ));
    }
    if hex::encode(&address[1..29]) != pkh {
        return Err(ApiError::validation(
            "Collateral Return Must Pay The Collateral Provider",
        ));
    }
    Ok(())
}

/// Require that this provider's PKH is in required_signers — a tx that
/// doesn't list us as a signer cannot legitimately consume our witness.
pub fn check_signers(body: &Value, pkh: &str) -> ApiResult<()> {
    let Some(field) = body.map_get(REQUIRED_SIGNERS) else {
        return Err(ApiError::validation(
            "Required Signers Does Not Exist In Body",
        ));
    };
    let Some(signers) = set_items(field) else {
        return Err(ApiError::validation("Required Signers Is Not A Set"));
    };

    for signer in signers {
        let Some(signer) = signer.as_bytes() else {
            return Err(ApiError::validation("Tx Signer Is Not Bytes"));
        };
        if hex::encode(signer) == pkh {
            return Ok(());
        }
    }
    Err(ApiError::validation(
        "Collateral Public Key Hash Is Not Being Used",
    ))
}

// --- internals -------------------------------------------------------------

/// Validate a `[txid, index]` reference and return its parts.
///
/// After `set_items` an entry is an array, so Python's tuple check maps onto
/// array-ness here. The index comes back as `None` when it is a legal
/// non-negative integer too large for `u64`: Python evaluates
/// `int(utxo[1]) == expected_idx`, which is simply false there, so an
/// oversized index must fail to match rather than being rejected or wrapping.
fn check_utxo_shape(utxo: &Value) -> ApiResult<(&[u8], Option<u64>)> {
    let Some(items) = utxo.as_array() else {
        return Err(ApiError::validation("UTxO Is Not A Tuple"));
    };
    if items.len() != 2 {
        return Err(ApiError::validation("UTxO Must Have Two Elements"));
    }
    let Some(txid) = items[0].as_bytes() else {
        return Err(ApiError::validation("TxId Is Not Bytes"));
    };
    if txid.len() != 32 {
        return Err(ApiError::validation("TxId Must Be 32 Bytes"));
    }

    let index = match &items[1] {
        Value::Int(index) => *index,
        // cbor2 turns a bignum into a plain Python `int`, so it passes the
        // isinstance guard there; only its sign is inspected afterwards.
        Value::BigInt { negative: true, .. } => {
            return Err(ApiError::validation("TxIdx Can't Be Negative"))
        }
        Value::BigInt { .. } => return Ok((txid, None)),
        // Booleans are deliberately not integers, matching Python's
        // `isinstance(x, int) and not isinstance(x, bool)`.
        _ => return Err(ApiError::validation("TxIdx Is Not An Int")),
    };
    if index < 0 {
        return Err(ApiError::validation("TxIdx Can't Be Negative"));
    }
    Ok((txid, u64::try_from(index).ok()))
}

fn is_collateral(txid: &[u8], index: Option<u64>, env_config: &EnvironmentConfig) -> bool {
    index == Some(env_config.txidx) && hex::encode(txid) == env_config.txid
}

#[cfg(test)]
mod tests {
    use super::*;

    const PKH: &str = "7c24c22d1dc252d31f6022ff22ccc838c2ab83a461172d7c2dae61f4";
    const COLLATERAL_TXID: &str =
        "e0f9a1641be97add010356e8f8ac278372e2acac24ee21f169f861cddb3c55c5";
    const MAX: usize = 16 * 1024;

    fn unhex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("test vector is hex")
    }

    fn env(txid: &str, txidx: u64) -> EnvironmentConfig {
        EnvironmentConfig {
            network: "--testnet-magic 1".to_string(),
            txid: txid.to_string(),
            txidx,
            koios_url: "http://127.0.0.1:1/ogmios".to_string(),
        }
    }

    fn body(entries: &[(i128, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(key, value)| (Value::Int(*key), value.clone()))
                .collect(),
        )
    }

    fn tagged(items: Vec<Value>) -> Value {
        Value::Tag(SET_TAG, Box::new(Value::Array(items)))
    }

    fn utxo(txid_hex: &str, index: i128) -> Value {
        Value::Array(vec![Value::Bytes(unhex(txid_hex)), Value::Int(index)])
    }

    fn detail(result: ApiResult<()>) -> String {
        result
            .expect_err("expected a validation error")
            .detail()
            .to_string()
    }

    /// A ban list backed by a temp file holding exactly these addresses.
    fn bans_with(addresses: &[&str]) -> (tempfile::TempDir, BanList) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bans.json");
        let document = serde_json::json!({ "addresses": addresses, "ips": [] });
        std::fs::write(&path, document.to_string()).expect("write bans");
        (dir, BanList::new(path))
    }

    fn no_bans() -> (tempfile::TempDir, BanList) {
        bans_with(&[])
    }

    // --- check_cbor_hex ----------------------------------------------------

    #[test]
    fn empty_hex_is_rejected() {
        let err = check_cbor_hex("", MAX).expect_err("empty");
        assert_eq!(err.detail(), "Tx Can't Be Empty");
    }

    #[test]
    fn non_hex_is_rejected() {
        for candidate in ["hello world", "abc", "0x0a", "ab c", "zz", "ab\u{a0}cd"] {
            let err = check_cbor_hex(candidate, MAX).expect_err(candidate);
            assert_eq!(err.detail(), "Invalid Hex Data In Tx", "{candidate}");
        }
    }

    #[test]
    fn hex_decoding_matches_bytes_fromhex() {
        // Both digit cases, and ASCII whitespace between complete pairs.
        for (candidate, expected) in [
            ("acab", "acab"),
            ("ACAB", "acab"),
            ("ac ab", "acab"),
            ("ac  ab", "acab"),
            ("ac\tab", "acab"),
            ("ac\nab", "acab"),
            ("ac\rab", "acab"),
            ("\u{b}acab", "acab"),
            ("\u{c}acab", "acab"),
            (" ", ""),
        ] {
            let bytes = check_cbor_hex(candidate, MAX).expect("decodes");
            assert_eq!(hex::encode(&bytes), expected, "{candidate:?}");
        }
    }

    #[test]
    fn oversized_tx_is_rejected_after_hex_decoding() {
        let payload = "00".repeat(MAX + 1);
        let err = check_cbor_hex(&payload, MAX).expect_err("too large");
        assert_eq!(err.detail(), "Tx Is Too Large");
        // Exactly at the cap is fine.
        assert!(check_cbor_hex(&"00".repeat(MAX), MAX).is_ok());
        // A huge but non-hex body still reports the hex failure first.
        let err = check_cbor_hex(&"zz".repeat(MAX + 1), MAX).expect_err("non hex");
        assert_eq!(err.detail(), "Invalid Hex Data In Tx");
    }

    // --- check_tx_body -----------------------------------------------------

    #[test]
    fn undecodable_cbor_is_rejected() {
        // 0xac is a 12-entry map header with nothing following it.
        let err = check_tx_body(&unhex("acab")).expect_err("bad cbor");
        assert_eq!(err.detail(), "Invalid CBOR Data In Tx");
        assert_eq!(
            check_tx_body(&[]).expect_err("empty").detail(),
            "Invalid CBOR Data In Tx"
        );
    }

    #[test]
    fn top_level_must_be_a_list() {
        // A CBOR map at the top level, as a real body would be.
        let err = check_tx_body(&unhex("a0")).expect_err("map");
        assert_eq!(err.detail(), "Tx Is Not A List");
    }

    #[test]
    fn trailing_data_is_rejected_after_the_list_check() {
        // cbor2.dumps([{}, {}, True, None]) + b"\x00"
        let err = check_tx_body(&unhex("84a0a0f5f600")).expect_err("trailing");
        assert_eq!(err.detail(), "Trailing Data After Tx");
        // Non-list first: trailing data behind a map still reports list-ness.
        let err = check_tx_body(&unhex("a000")).expect_err("map plus trailing");
        assert_eq!(err.detail(), "Tx Is Not A List");
    }

    #[test]
    fn envelope_must_have_exactly_four_elements() {
        for hex in ["83a0a0f5", "85a0a0f5f600", "80"] {
            let err = check_tx_body(&unhex(hex)).expect_err(hex);
            assert_eq!(err.detail(), "Tx Must Have Four Elements", "{hex}");
        }
    }

    #[test]
    fn body_must_be_a_map_and_is_checked_before_the_witness_set() {
        // [bytes32, [], true, null] — both body and witness set are wrong.
        let tx = format!("845820{}80f5f6", "e0".repeat(32));
        let err = check_tx_body(&unhex(&tx)).expect_err("body");
        assert_eq!(err.detail(), "Tx Body Is Not A Dict");
    }

    #[test]
    fn witness_set_must_be_a_map() {
        // cbor2.dumps([{}, [], True, None])
        let err = check_tx_body(&unhex("84a080f5f6")).expect_err("witness set");
        assert_eq!(err.detail(), "Witness Set Is Not A Dict");
    }

    #[test]
    fn is_valid_must_be_a_true_boolean() {
        // The integer 0 is not a bool, and CBOR true/false are not integers.
        let err = check_tx_body(&unhex("84a0a000f6")).expect_err("int flag");
        assert_eq!(err.detail(), "Boolean Is Not A Bool");
        let err = check_tx_body(&unhex("84a0a001f6")).expect_err("int flag");
        assert_eq!(err.detail(), "Boolean Is Not A Bool");
        let err = check_tx_body(&unhex("84a0a0f4f6")).expect_err("false flag");
        assert_eq!(err.detail(), "Boolean Can't Be False");
    }

    #[test]
    fn a_well_formed_envelope_returns_its_body() {
        // [{0: 1}, {}, true, null]
        let decoded = check_tx_body(&unhex("84a10001a0f5f6")).expect("valid envelope");
        assert_eq!(decoded.map_get(0), Some(&Value::Int(1)));
    }

    // --- set_items ---------------------------------------------------------

    #[test]
    fn set_items_accepts_both_conway_encodings() {
        let untagged = Value::Array(vec![Value::Int(1), Value::Int(2)]);
        assert_eq!(
            set_items(&untagged),
            Some(vec![&Value::Int(1), &Value::Int(2)])
        );
        let tagged_form = tagged(vec![Value::Int(1)]);
        assert_eq!(set_items(&tagged_form), Some(vec![&Value::Int(1)]));
    }

    #[test]
    fn set_items_rejects_other_shapes() {
        for value in [
            Value::Int(5),
            Value::Text("abc".into()),
            Value::Bytes(vec![1]),
            Value::Null,
            Value::Map(vec![]),
            Value::Bool(true),
            // Wrong tag number, and tag 258 around a non-array.
            Value::Tag(24, Box::new(Value::Array(vec![]))),
            Value::Tag(SET_TAG, Box::new(Value::Int(1))),
        ] {
            assert!(set_items(&value).is_none(), "{value:?}");
        }
    }

    #[test]
    fn set_items_dedupes_structurally_and_keeps_wire_order() {
        let entry = utxo(COLLATERAL_TXID, 0);
        let other = utxo(COLLATERAL_TXID, 1);
        let value = Value::Array(vec![entry.clone(), other.clone(), entry.clone()]);
        assert_eq!(set_items(&value), Some(vec![&entry, &other]));
        // Nested containers and unequal types are distinguished.
        let mixed = Value::Array(vec![
            Value::Int(0),
            Value::Bool(false),
            Value::Array(vec![Value::Int(0)]),
        ]);
        assert_eq!(set_items(&mixed).map(|items| items.len()), Some(3));
    }

    // --- check_inputs ------------------------------------------------------

    #[test]
    fn inputs_field_must_exist_and_be_a_set() {
        let config = env(COLLATERAL_TXID, 0);
        assert_eq!(
            detail(check_inputs(&body(&[]), &config)),
            "Inputs Does Not Exist In Body"
        );
        for value in [
            Value::Map(vec![]),
            Value::Int(5),
            Value::Text("abc".into()),
            Value::Bytes(b"abc".to_vec()),
            Value::Null,
        ] {
            assert_eq!(
                detail(check_inputs(&body(&[(INPUTS, value)]), &config)),
                "Inputs Are Not A Set"
            );
        }
    }

    #[test]
    fn spending_the_collateral_is_rejected_in_both_encodings() {
        let config = env(COLLATERAL_TXID, 0);
        let tagged_body = body(&[(INPUTS, tagged(vec![utxo(COLLATERAL_TXID, 0)]))]);
        assert_eq!(
            detail(check_inputs(&tagged_body, &config)),
            "Collateral Is Being Spent In Tx"
        );
        let untagged_body = body(&[(INPUTS, Value::Array(vec![utxo(COLLATERAL_TXID, 0)]))]);
        assert_eq!(
            detail(check_inputs(&untagged_body, &config)),
            "Collateral Is Being Spent In Tx"
        );
    }

    #[test]
    fn unrelated_inputs_pass() {
        let config = env(COLLATERAL_TXID, 0);
        let inputs = tagged(vec![
            utxo(&"22".repeat(32), 0),
            // Same txid, different index — not our UTxO.
            utxo(COLLATERAL_TXID, 1),
        ]);
        assert!(check_inputs(&body(&[(INPUTS, inputs)]), &config).is_ok());
        // Empty input sets are structurally fine here.
        assert!(check_inputs(&body(&[(INPUTS, tagged(vec![]))]), &config).is_ok());
    }

    #[test]
    fn malformed_input_references_are_named_precisely() {
        let config = env(&"ff".repeat(32), 0);
        let cases: Vec<(Value, &str)> = vec![
            (Value::Int(1), "UTxO Is Not A Tuple"),
            (Value::Bytes(vec![1]), "UTxO Is Not A Tuple"),
            (
                Value::Map(vec![(Value::Int(0), Value::Int(0))]),
                "UTxO Is Not A Tuple",
            ),
            (
                Value::Array(vec![Value::Bytes(unhex(&"11".repeat(32)))]),
                "UTxO Must Have Two Elements",
            ),
            (
                Value::Array(vec![
                    Value::Bytes(unhex(&"11".repeat(32))),
                    Value::Int(0),
                    Value::Int(1),
                ]),
                "UTxO Must Have Two Elements",
            ),
            (
                Value::Array(vec![Value::Int(1), Value::Int(0)]),
                "TxId Is Not Bytes",
            ),
            (
                Value::Array(vec![Value::Bytes(unhex(&"11".repeat(31))), Value::Int(0)]),
                "TxId Must Be 32 Bytes",
            ),
            (
                Value::Array(vec![
                    Value::Bytes(unhex(&"11".repeat(32))),
                    Value::Bool(true),
                ]),
                "TxIdx Is Not An Int",
            ),
            (
                Value::Array(vec![
                    Value::Bytes(unhex(&"11".repeat(32))),
                    Value::Bool(false),
                ]),
                "TxIdx Is Not An Int",
            ),
            (
                Value::Array(vec![
                    Value::Bytes(unhex(&"11".repeat(32))),
                    Value::Text("0".into()),
                ]),
                "TxIdx Is Not An Int",
            ),
            (
                Value::Array(vec![Value::Bytes(unhex(&"11".repeat(32))), Value::Int(-1)]),
                "TxIdx Can't Be Negative",
            ),
            (
                Value::Array(vec![
                    Value::Bytes(unhex(&"11".repeat(32))),
                    Value::BigInt {
                        negative: true,
                        magnitude: vec![0xff; 17],
                    },
                ]),
                "TxIdx Can't Be Negative",
            ),
        ];
        for (entry, message) in cases {
            let field = tagged(vec![entry.clone()]);
            assert_eq!(
                detail(check_inputs(&body(&[(INPUTS, field)]), &config)),
                message,
                "{entry:?}"
            );
        }
    }

    #[test]
    fn an_index_beyond_u64_never_matches_and_never_panics() {
        // Python compares `int(utxo[1]) == expected_idx`, which is false for
        // any oversized index; neither a wrap nor a rejection is correct.
        let config = env(COLLATERAL_TXID, 0);
        for oversized in [
            Value::Int(i128::from(u64::MAX) + 1),
            Value::BigInt {
                negative: false,
                magnitude: vec![0xff; 17],
            },
        ] {
            let field = tagged(vec![Value::Array(vec![
                Value::Bytes(unhex(COLLATERAL_TXID)),
                oversized,
            ])]);
            assert!(check_inputs(&body(&[(INPUTS, field)]), &config).is_ok());
        }
    }

    // --- check_outputs -----------------------------------------------------

    #[test]
    fn outputs_field_must_exist_and_be_a_list() {
        let (_dir, bans) = no_bans();
        assert_eq!(
            detail(check_outputs(&body(&[]), &bans)),
            "Outputs Does Not Exist In Body"
        );
        assert_eq!(
            detail(check_outputs(
                &body(&[(OUTPUTS, Value::Map(vec![]))]),
                &bans
            )),
            "Outputs Are Not A List"
        );
        assert_eq!(
            detail(check_outputs(&body(&[(OUTPUTS, tagged(vec![]))]), &bans)),
            "Outputs Are Not A List"
        );
    }

    #[test]
    fn outputs_accept_shelley_and_babbage_encodings() {
        let (_dir, bans) = no_bans();
        let address = Value::Bytes(unhex(&format!("60{}", "ab".repeat(28))));
        let shelley = Value::Array(vec![address.clone(), Value::Int(5_000_000)]);
        let babbage = Value::Map(vec![
            (Value::Int(0), address),
            (Value::Int(1), Value::Int(5_000_000)),
        ]);
        let field = Value::Array(vec![shelley, babbage]);
        assert!(check_outputs(&body(&[(OUTPUTS, field)]), &bans).is_ok());
    }

    #[test]
    fn malformed_outputs_are_named_precisely() {
        let (_dir, bans) = no_bans();
        let cases: Vec<(Value, &str)> = vec![
            (Value::Int(1), "UTxO Is Not A List Or Dict"),
            (Value::Bytes(vec![1]), "UTxO Is Not A List Or Dict"),
            (Value::Null, "UTxO Is Not A List Or Dict"),
            (Value::Array(vec![]), "TxId Does Not Exist In UTxO"),
            (
                Value::Map(vec![(Value::Int(1), Value::Int(0))]),
                "TxId Does Not Exist In UTxO",
            ),
            (
                Value::Array(vec![Value::Int(1), Value::Int(2)]),
                "TxId Is Not Bytes",
            ),
            (
                Value::Map(vec![(Value::Int(0), Value::Text("addr".into()))]),
                "TxId Is Not Bytes",
            ),
        ];
        for (output, message) in cases {
            let field = Value::Array(vec![output.clone()]);
            assert_eq!(
                detail(check_outputs(&body(&[(OUTPUTS, field)]), &bans)),
                message,
                "{output:?}"
            );
        }
    }

    #[test]
    fn a_banned_output_address_is_reported_with_its_hex() {
        let address = "7025891024cd6915ab6f7d85d43869c7bfc7021b7008bad86e70a7c6ce";
        let (_dir, bans) = bans_with(&[address]);
        let field = Value::Array(vec![Value::Array(vec![
            Value::Bytes(unhex(address)),
            Value::Int(1_000_000),
        ])]);
        assert_eq!(
            detail(check_outputs(&body(&[(OUTPUTS, field)]), &bans)),
            format!("The Address: {address} Is Banned")
        );
    }

    // --- check_collateral --------------------------------------------------

    #[test]
    fn collateral_field_must_exist_and_be_a_set() {
        let config = env(COLLATERAL_TXID, 0);
        assert_eq!(
            detail(check_collateral(&body(&[]), &config)),
            "Collateral Does Not Exist In Body"
        );
        assert_eq!(
            detail(check_collateral(
                &body(&[(COLLATERAL_INPUTS, Value::Map(vec![]))]),
                &config
            )),
            "Collateral Is Not A Set"
        );
    }

    #[test]
    fn exactly_one_collateral_input_is_required() {
        let config = env(&"11".repeat(32), 0);
        let two = tagged(vec![utxo(&"11".repeat(32), 0), utxo(&"22".repeat(32), 1)]);
        assert_eq!(
            detail(check_collateral(
                &body(&[(COLLATERAL_INPUTS, two)]),
                &config
            )),
            "Exactly One Collateral Input Is Required"
        );
        let none = tagged(vec![]);
        assert_eq!(
            detail(check_collateral(
                &body(&[(COLLATERAL_INPUTS, none)]),
                &config
            )),
            "Exactly One Collateral Input Is Required"
        );
    }

    #[test]
    fn untagged_duplicates_collapse_like_the_tagged_form() {
        // A tagged set would dedupe these at decode time in Python; the
        // untagged list must not therefore trip the "exactly one" rule.
        let config = env(&"11".repeat(32), 0);
        let field = Value::Array(vec![utxo(&"11".repeat(32), 0), utxo(&"11".repeat(32), 0)]);
        assert!(check_collateral(&body(&[(COLLATERAL_INPUTS, field)]), &config).is_ok());
    }

    #[test]
    fn a_foreign_collateral_is_rejected() {
        let config = env(&"11".repeat(32), 0);
        for wrong in [utxo(&"99".repeat(32), 0), utxo(&"11".repeat(32), 1)] {
            let field = Value::Array(vec![wrong.clone()]);
            assert_eq!(
                detail(check_collateral(
                    &body(&[(COLLATERAL_INPUTS, field)]),
                    &config
                )),
                "Collateral Is Not Being Used In Tx",
                "{wrong:?}"
            );
        }
    }

    /// A body that carries field 13 twice under keys a Python `dict` would
    /// merge — `13` and `13.0` — must be refused, not silently validated
    /// against whichever copy this implementation happens to read.
    ///
    /// Python's `cbor2` builds a dict, so `body[13]` there is the *float*
    /// entry's value (last write wins); `Value::map_get` matched integer keys
    /// only and would have read the other one. Two implementations validating
    /// different collateral out of the same bytes is exactly the class of
    /// disagreement this service cannot afford, so `map_get` reports the field
    /// as absent and the transaction is rejected. Such a body is also rejected
    /// by the ledger's own decoder in phase 1, so nothing legitimate is lost.
    #[test]
    fn an_aliased_collateral_field_is_refused_rather_than_guessed() {
        let config = env(&"11".repeat(32), 3);
        let good = Value::Array(vec![utxo(&"11".repeat(32), 3)]);
        let decoy = Value::Array(vec![utxo(&"99".repeat(32), 7)]);
        // The correct collateral under key 13, a decoy under 13.0.
        let aliased = Value::Map(vec![
            (Value::Int(COLLATERAL_INPUTS), good.clone()),
            (Value::Float(13.0), decoy.clone()),
        ]);
        assert_eq!(
            detail(check_collateral(&aliased, &config)),
            "Collateral Does Not Exist In Body"
        );
        // And with the two entries the other way round.
        let reversed = Value::Map(vec![
            (Value::Float(13.0), decoy),
            (Value::Int(COLLATERAL_INPUTS), good.clone()),
        ]);
        assert_eq!(
            detail(check_collateral(&reversed, &config)),
            "Collateral Does Not Exist In Body"
        );
        // A bool key aliases 0 and 1, not 13, so this body still validates.
        let unaliased = Value::Map(vec![
            (Value::Int(COLLATERAL_INPUTS), good),
            (Value::Bool(true), Value::Int(0)),
        ]);
        assert!(check_collateral(&unaliased, &config).is_ok());
    }

    #[test]
    fn the_configured_collateral_is_accepted_in_both_encodings() {
        let config = env(&"11".repeat(32), 3);
        for field in [
            tagged(vec![utxo(&"11".repeat(32), 3)]),
            Value::Array(vec![utxo(&"11".repeat(32), 3)]),
        ] {
            assert!(check_collateral(&body(&[(COLLATERAL_INPUTS, field)]), &config).is_ok());
        }
    }

    // --- check_collateral_return -------------------------------------------

    #[test]
    fn an_absent_collateral_return_is_allowed() {
        assert!(check_collateral_return(&body(&[]), PKH).is_ok());
    }

    #[test]
    fn a_return_to_the_provider_key_is_allowed_in_both_encodings() {
        let address = Value::Bytes(unhex(&format!("60{PKH}")));
        let shelley = Value::Array(vec![address.clone(), Value::Int(1_000_000)]);
        assert!(check_collateral_return(&body(&[(COLLATERAL_RETURN, shelley)]), PKH).is_ok());
        let babbage = Value::Map(vec![
            (Value::Int(0), address),
            (Value::Int(1), Value::Int(1_000_000)),
        ]);
        assert!(check_collateral_return(&body(&[(COLLATERAL_RETURN, babbage)]), PKH).is_ok());
        // Trailing staking bytes are fine; only the payment credential matters.
        let base = Value::Array(vec![
            Value::Bytes(unhex(&format!("00{PKH}{}", "cd".repeat(28)))),
            Value::Int(1),
        ]);
        assert!(check_collateral_return(&body(&[(COLLATERAL_RETURN, base)]), PKH).is_ok());
    }

    #[test]
    fn a_return_to_anyone_else_is_rejected() {
        let attacker = Value::Array(vec![
            Value::Bytes(unhex(&format!("60{}", "aa".repeat(28)))),
            Value::Int(1_000_000),
        ]);
        assert_eq!(
            detail(check_collateral_return(
                &body(&[(COLLATERAL_RETURN, attacker)]),
                PKH
            )),
            "Collateral Return Must Pay The Collateral Provider"
        );
    }

    #[test]
    fn a_script_payment_credential_is_rejected_even_with_our_hash() {
        // Odd address-type nibbles carry a script hash; the provider key
        // cannot control the funds even when the bytes match.
        for header in ["70", "10", "30", "50"] {
            let output = Value::Array(vec![
                Value::Bytes(unhex(&format!("{header}{PKH}{}", "cd".repeat(28)))),
                Value::Int(1),
            ]);
            assert_eq!(
                detail(check_collateral_return(
                    &body(&[(COLLATERAL_RETURN, output)]),
                    PKH
                )),
                "Collateral Return Must Not Pay A Script Address",
                "{header}"
            );
        }
    }

    #[test]
    fn a_malformed_collateral_return_is_named_precisely() {
        assert_eq!(
            detail(check_collateral_return(
                &body(&[(COLLATERAL_RETURN, Value::Int(5))]),
                PKH
            )),
            "Collateral Return Is Not A List Or Dict"
        );
        assert_eq!(
            detail(check_collateral_return(
                &body(&[(COLLATERAL_RETURN, Value::Array(vec![]))]),
                PKH
            )),
            "Collateral Return Has No Address"
        );
        assert_eq!(
            detail(check_collateral_return(
                &body(&[(
                    COLLATERAL_RETURN,
                    Value::Map(vec![(Value::Int(1), Value::Int(0))])
                )]),
                PKH
            )),
            "Collateral Return Has No Address"
        );
        for malformed in [
            Value::Bytes(vec![]),
            Value::Bytes(vec![0x60, 0x00]),
            // 28 bytes: one short of a header plus a payment credential.
            Value::Bytes(unhex(&format!("60{}", "aa".repeat(27)))),
            Value::Text("not-bytes".into()),
            Value::Int(5),
        ] {
            let output = Value::Array(vec![malformed.clone(), Value::Int(1)]);
            assert_eq!(
                detail(check_collateral_return(
                    &body(&[(COLLATERAL_RETURN, output)]),
                    PKH
                )),
                "Collateral Return Address Is Malformed",
                "{malformed:?}"
            );
        }
    }

    // --- check_signers -----------------------------------------------------

    #[test]
    fn required_signers_must_exist_and_be_a_set() {
        assert_eq!(
            detail(check_signers(&body(&[]), PKH)),
            "Required Signers Does Not Exist In Body"
        );
        assert_eq!(
            detail(check_signers(
                &body(&[(REQUIRED_SIGNERS, Value::Map(vec![]))]),
                PKH
            )),
            "Required Signers Is Not A Set"
        );
    }

    #[test]
    fn our_pkh_must_be_a_required_signer() {
        let ours = Value::Bytes(unhex(PKH));
        for field in [
            tagged(vec![ours.clone()]),
            Value::Array(vec![ours.clone()]),
            tagged(vec![Value::Bytes(unhex(&"aa".repeat(28))), ours]),
        ] {
            assert!(check_signers(&body(&[(REQUIRED_SIGNERS, field)]), PKH).is_ok());
        }
    }

    #[test]
    fn a_signer_set_without_our_pkh_is_rejected() {
        let field = tagged(vec![Value::Bytes(unhex(&"aa".repeat(28)))]);
        assert_eq!(
            detail(check_signers(&body(&[(REQUIRED_SIGNERS, field)]), PKH)),
            "Collateral Public Key Hash Is Not Being Used"
        );
        assert_eq!(
            detail(check_signers(
                &body(&[(REQUIRED_SIGNERS, tagged(vec![]))]),
                PKH
            )),
            "Collateral Public Key Hash Is Not Being Used"
        );
    }

    #[test]
    fn a_non_byte_signer_is_rejected() {
        for entry in [
            Value::Int(1),
            Value::Text(PKH.into()),
            Value::Array(vec![Value::Bytes(unhex(PKH))]),
        ] {
            let field = tagged(vec![entry.clone()]);
            assert_eq!(
                detail(check_signers(&body(&[(REQUIRED_SIGNERS, field)]), PKH)),
                "Tx Signer Is Not Bytes",
                "{entry:?}"
            );
        }
    }

    // --- duplicate body keys -----------------------------------------------

    #[test]
    fn duplicate_body_keys_read_last_wins_like_a_python_dict() {
        let config = env(COLLATERAL_TXID, 0);
        let duplicated = Value::Map(vec![
            (Value::Int(INPUTS), tagged(vec![utxo(&"22".repeat(32), 0)])),
            (Value::Int(INPUTS), tagged(vec![utxo(COLLATERAL_TXID, 0)])),
        ]);
        assert_eq!(
            detail(check_inputs(&duplicated, &config)),
            "Collateral Is Being Spent In Tx"
        );
    }

    // --- end to end over the decoder ---------------------------------------

    #[test]
    fn a_body_decoded_from_the_wire_flows_through_every_check() {
        let (_dir, bans) = no_bans();
        let config = env(COLLATERAL_TXID, 0);
        let other = "22".repeat(32);
        let address = format!("60{}", "ab".repeat(28));
        // [{0: 258([[22*32, 0]]), 1: [[60||ab*28, 5000000]],
        //   13: 258([[collateral, 0]]), 14: 258([pkh])}, {}, true, null]
        let tx = format!(
            "84a4\
               00d9010281825820{other}00\
               018182581d{address}1a004c4b40\
               0dd9010281825820{COLLATERAL_TXID}00\
               0ed9010281581c{PKH}\
             a0f5f6"
        );
        let raw = check_cbor_hex(&tx, MAX).expect("hex decodes");
        let decoded = check_tx_body(&raw).expect("envelope is valid");
        assert!(check_inputs(&decoded, &config).is_ok());
        assert!(check_outputs(&decoded, &bans).is_ok());
        assert!(check_collateral(&decoded, &config).is_ok());
        assert!(check_collateral_return(&decoded, PKH).is_ok());
        assert!(check_signers(&decoded, PKH).is_ok());
    }
}
