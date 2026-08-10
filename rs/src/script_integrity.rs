//! Cardano script-data-hash verification without a ledger SDK dependency.
//!
//! The script data hash in transaction-body field 11 commits to the *original
//! CBOR bytes* of the redeemers and datums in the witness set, followed by the
//! language views derived from the protocol cost models. Re-encoding decoded
//! values is not equivalent: the ledger deliberately memoizes the original
//! bytes for this calculation.
//!
//! This module therefore uses `cbor::Decoder`'s byte-span tracking to slice
//! witness fields 4 and 5 out of the submitted transaction verbatim.

use std::collections::BTreeMap;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use subtle::{Choice, ConstantTimeEq};

use crate::cbor::{CborError, Decoder, Value, SET_TAG};

/// Plutus language id (0 = V1, 1 = V2, 2 = V3, 3 = V4) to its cost model.
pub type CostModels = BTreeMap<u8, Vec<i64>>;

/// PlutusV1 through PlutusV4.
pub const MAX_LANGUAGE: u8 = 3;

/// Body field holding the script data hash.
const SCRIPT_DATA_HASH: i128 = 11;
/// Witness-set field holding the datums.
const DATUMS: i128 = 4;
/// Witness-set field holding the redeemers.
const REDEEMERS: i128 = 5;

/// Cardano hashes the script data with Blake2b-256.
type Blake2b256 = Blake2b<U32>;

/// The transaction cannot be used to establish script-data binding.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct ScriptIntegrityError(pub String);

fn error(message: &str) -> ScriptIntegrityError {
    ScriptIntegrityError(message.to_owned())
}

/// Read an array/map header, reporting the Python cursor's exact messages.
///
/// The distinction between a missing header byte and a truncated length is
/// operator vocabulary that reaches the logs through `check_valid_tx`, so it
/// is worth keeping even though the caller-facing string is the same.
fn container_length(
    decoder: &mut Decoder<'_>,
    expected_major: u8,
) -> Result<Option<u64>, ScriptIntegrityError> {
    if decoder.is_at_end() {
        return Err(error("truncated CBOR"));
    }
    decoder
        .container_header(expected_major)
        .map_err(|err| match err {
            CborError::UnexpectedMajor { .. } => error(if expected_major == 4 {
                "expected CBOR array"
            } else {
                "expected CBOR map"
            }),
            CborError::Truncated => error("truncated CBOR container length"),
            _ => error("invalid CBOR container length"),
        })
}

/// One entry of a transaction map: its key as an integer (when it fits),
/// the decoded value, and the value's exact wire bytes.
struct MapItem<'a> {
    key: Option<i128>,
    value: Value,
    raw: &'a [u8],
}

/// Walk a map, returning decoded keys and *raw* value bytes, rejecting
/// duplicates.
///
/// Duplicates are rejected here even though `Value::map_get` elsewhere
/// reproduces `cbor2`'s last-wins `dict` collapse: a second field 5 would let
/// the redeemer bytes we hash differ from the ones a node reads.
fn map_items<'a>(decoder: &mut Decoder<'a>) -> Result<Vec<MapItem<'a>>, ScriptIntegrityError> {
    let length = container_length(decoder, 5)?;
    let mut seen: Vec<Value> = Vec::new();
    let mut items: Vec<MapItem<'a>> = Vec::new();
    let mut remaining = length;
    loop {
        match remaining {
            Some(0) => return Ok(items),
            // Indefinite maps end at the break; a truncated one runs out of
            // input in decode_value below instead.
            None if decoder.at_break() => {
                decoder
                    .consume_break()
                    .map_err(|_| error("missing CBOR break"))?;
                return Ok(items);
            }
            _ => {}
        }
        let key = decoder
            .decode_value()
            .map_err(|_| error("invalid CBOR value"))?;
        // A CBOR boolean is not an integer, matching Python's
        // `isinstance(key, int) and not isinstance(key, bool)` guard.
        if !matches!(key, Value::Int(_) | Value::BigInt { .. }) {
            return Err(error("transaction map key is not an integer"));
        }
        if seen.contains(&key) {
            return Err(error("transaction map key is duplicated"));
        }
        let key_index = key.as_int();
        seen.push(key);
        let (value, raw) = decoder
            .decode_value_raw()
            .map_err(|_| error("invalid CBOR value"))?;
        items.push(MapItem {
            key: key_index,
            value,
            raw,
        });
        if let Some(count) = remaining.as_mut() {
            *count -= 1;
        }
    }
}

/// The ledger omits TxDats bytes when the decoded collection is empty.
fn datum_bytes<'a>(value: &Value, raw: &'a [u8]) -> &'a [u8] {
    let value = value.as_tag(SET_TAG).unwrap_or(value);
    let empty = match value {
        Value::Array(items) => items.is_empty(),
        Value::Map(entries) => entries.is_empty(),
        _ => false,
    };
    if empty {
        &[]
    } else {
        raw
    }
}

/// `(committed body hash, raw redeemers bytes, raw non-empty datums bytes)` —
/// the three exact byte slices field 11 commits to.
pub type ScriptDataParts = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Return `(committed body hash, raw redeemers bytes, raw non-empty datums
/// bytes)`.
///
/// Only the transaction envelope and the two relevant maps are traversed. The
/// caller's normal transaction validators remain responsible for the rest of
/// the transaction schema.
///
/// Duplicate integer keys in the body or witness-set maps are rejected here
/// (the Python cursor does the same), even though the general decoder used by
/// the CBOR validators takes the last-wins `dict` semantics of `cbor2`.
pub fn script_data_parts(tx_cbor_hex: &str) -> Result<ScriptDataParts, ScriptIntegrityError> {
    let data =
        hex::decode(tx_cbor_hex).map_err(|_| error("transaction is not hexadecimal CBOR"))?;

    // `cbor::Decoder` interprets only the bignum tags, where `cbor2` runs a
    // semantic decoder per tag and raises on a payload that does not fit its
    // expectation (tag 0 without a date string, tag 258 over unhashable
    // items). Such a transaction is rejected here one step later — by the
    // structural body validators, or by the hash simply not matching — rather
    // than as a decode failure. Nothing that parses in both implementations
    // yields different bytes; that is what the differential corpus checks.
    let mut decoder = Decoder::new(&data);
    let tx_length = container_length(&mut decoder, 4)?;
    if !matches!(tx_length, Some(4) | None) {
        return Err(error("transaction must have four elements"));
    }

    // A malformed field 11 is not reported until the whole envelope has been
    // walked, so a truncated transaction still reports truncation first.
    let mut committed_hash: Option<Value> = None;
    for item in map_items(&mut decoder)? {
        if item.key == Some(SCRIPT_DATA_HASH) {
            committed_hash = Some(item.value);
        }
    }

    let mut redeemers: Option<Vec<u8>> = None;
    let mut datums: Vec<u8> = Vec::new();
    for item in map_items(&mut decoder)? {
        if item.key == Some(REDEEMERS) {
            redeemers = Some(item.raw.to_vec());
        } else if item.key == Some(DATUMS) {
            datums = datum_bytes(&item.value, item.raw).to_vec();
        }
    }

    // is_valid and auxiliary_data
    for _ in 0..2 {
        decoder
            .decode_value()
            .map_err(|_| error("invalid CBOR value"))?;
    }
    if tx_length.is_none() {
        decoder
            .consume_break()
            .map_err(|_| error("missing CBOR break"))?;
    }
    if decoder.position() != data.len() {
        return Err(error("transaction has trailing CBOR data"));
    }

    let committed_hash = match committed_hash.as_ref().and_then(Value::as_bytes) {
        Some(hash) if hash.len() == 32 => hash.to_vec(),
        _ => return Err(error("transaction has no valid script data hash")),
    };
    let Some(redeemers) = redeemers else {
        return Err(error("transaction has no redeemers"));
    };
    Ok((committed_hash, redeemers, datums))
}

/// Reject cost models the language-view encoder cannot faithfully represent.
///
/// The Python version also range-checks each parameter against `int64`; here
/// the `i64` element type carries that guarantee, so the corresponding
/// "protocol cost model parameter is invalid" path is unrepresentable.
fn validate_cost_models(cost_models: &CostModels) -> Result<(), ScriptIntegrityError> {
    if cost_models.is_empty() {
        return Err(error("protocol cost models are empty"));
    }
    for (language, costs) in cost_models {
        if *language > MAX_LANGUAGE {
            return Err(error("protocol cost model language is invalid"));
        }
        if costs.is_empty() {
            return Err(error("protocol cost model is invalid"));
        }
    }
    Ok(())
}

fn language_view_pair(language: u8, costs: &[i64]) -> (Vec<u8>, Vec<u8>) {
    if language == 0 {
        // PlutusV1 preserves the original Alonzo encoding bug: its language
        // key and indefinite-length parameter list are each wrapped in a CBOR
        // byte string (the historical "double-bagging").
        let key = crate::cbor::encode_bytes(&crate::cbor::encode_uint(0));
        let mut indefinite = vec![0x9F];
        for cost in costs {
            indefinite.extend_from_slice(&crate::cbor::encode_int(*cost));
        }
        indefinite.push(0xFF);
        return (key, crate::cbor::encode_bytes(&indefinite));
    }
    let items: Vec<Vec<u8>> = costs
        .iter()
        .map(|cost| crate::cbor::encode_int(*cost))
        .collect();
    (
        crate::cbor::encode_uint(u64::from(language)),
        crate::cbor::encode_array(&items),
    )
}

/// Serialize already-encoded `(key, value)` pairs into the view map.
fn assemble_language_views(pairs: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>, ScriptIntegrityError> {
    // The ledger orders the already-encoded keys using canonical CBOR shortlex
    // ordering. This notably places V2/V3/V4 before V1 in a mixed map.
    let mut ordered: Vec<&(Vec<u8>, Vec<u8>)> = pairs.iter().collect();
    ordered.sort_by(|left, right| {
        left.0
            .len()
            .cmp(&right.0.len())
            .then_with(|| left.0.cmp(&right.0))
    });
    if ordered.len() >= 24 {
        // Currently impossible, but keep the encoder honest.
        return Err(error("too many protocol cost models"));
    }
    let mut out = vec![0xA0 + ordered.len() as u8];
    for (key, value) in ordered {
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }
    Ok(out)
}

/// Encode the ledger language-view map for one selected model subset.
pub fn encode_language_views(cost_models: &CostModels) -> Result<Vec<u8>, ScriptIntegrityError> {
    validate_cost_models(cost_models)?;
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = cost_models
        .iter()
        .map(|(language, costs)| language_view_pair(*language, costs))
        .collect();
    assemble_language_views(&pairs)
}

fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Calculate a script data hash from exact witness bytes and models.
pub fn calculate_script_data_hash(
    redeemers: &[u8],
    datums: &[u8],
    cost_models: &CostModels,
) -> Result<[u8; 32], ScriptIntegrityError> {
    let language_views = encode_language_views(cost_models)?;
    Ok(blake2b_256(&[redeemers, datums, &language_views]))
}

/// Check field 11 against every possible current language-model subset.
///
/// The language set cannot be determined from the witness set alone because
/// scripts may be supplied by reference inputs. Trying all non-empty subsets
/// still proves that the submitted redeemers/datums are what field 11 commits
/// to; a wrong subset is rejected later by ledger phase-1 checks. With four
/// supported Plutus versions this is at most 15 hashes.
///
/// The comparison is constant-time and does not short-circuit, so the number
/// of comparisons is independent of which subset matches.
pub fn verify_script_data_hash(
    tx_cbor_hex: &str,
    cost_models: &CostModels,
) -> Result<bool, ScriptIntegrityError> {
    let (committed_hash, redeemers, datums) = script_data_parts(tx_cbor_hex)?;
    validate_cost_models(cost_models)?;

    // Encode each language's (key, value) pair exactly once. Re-deriving them
    // per subset re-encodes every cost-model integer up to 15 times, and
    // PlutusV1's encoder emits one integer per cost parameter — roughly 2000
    // redundant encodings per signing request.
    let encoded: Vec<(Vec<u8>, Vec<u8>)> = cost_models
        .iter()
        .map(|(language, costs)| language_view_pair(*language, costs))
        .collect();

    let mut prefix = redeemers;
    prefix.extend_from_slice(&datums);

    let mut matched = Choice::from(0u8);
    // Languages are capped at four, so the subset mask stays inside a u8.
    for mask in 1u32..(1u32 << encoded.len()) {
        let selected: Vec<(Vec<u8>, Vec<u8>)> = encoded
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, pair)| pair.clone())
            .collect();
        let language_views = assemble_language_views(&selected)?;
        let candidate = blake2b_256(&[&prefix, language_views.as_slice()]);
        // Not short-circuiting keeps the comparison count independent of
        // which subset matches.
        matched |= candidate.ct_eq(committed_hash.as_slice());
    }
    Ok(bool::from(matched))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `a182000082d87980820a14` — a one-entry Conway redeemer map.
    const REDEEMER_HEX: &str = "a182000082d87980820a14";

    /// Mainnet transaction accepted on-chain in epoch 511, whose body field 11
    /// commits to the PlutusV3 model below.
    const MAINNET_TX_HEX: &str = "84a900d9010282825820cb2cc3a624803cf82d85f191b33990de574b1d7286f1118b9ed85bc9e8d434f100825820cb2cc3a624803cf82d85f191b33990de574b1d7286f1118b9ed85bc9e8d434f1010dd90102818258201e0b413409dd9591b2a69bca80d7d776e8bb5130f02af0bf886e08ce5b6e183a0012d90102818258205d8a5d172c7edf3c491f418d33a69bee784e35593163eaf39853f292b81fd95c010182a300581d7047a9877e549b91e775bd40fae36dfbdac072098fb382822faf47b4df01821a0041b31aa1581c0d87a0d951d4d2b04207a8bdafa39c24876c0cb9659045c2365102cca15820b786c5adf265db88e0c6287abb5dbc25202d50ab4b504bc342734bdd24b9e50001028201d8185902d4d8799f581cf4a78bbff6d5e7e492915986abc495382247af659018451a25cec92cd8799f9f581cd858ecf3e73e18bef8383a16e856778e033cfd1c8867c70dc9b68b42581c10a20db9464d89dab407b3397e67facf83db8d442e601b627c0a351f581c121ce13907d40c7a598d182ed751d39279cf30d50decb17151b3a587ff02ffd8799f581c1e3105f23f2ac91b3fb4c35fa4fe301421028e356e114944e902005bd8799f581c8f7b0ce283a92df9a3b69ac0b8f10d8bc8bcf8fbd1fe72596ee8bd6c40ffffd8799f581ca7c1a7fa1f60a3625002664e5aade3277666f370c1456825e2aa7e16581c988fee4370c5b5855ed3c52ea3d5e1e01371b39bf479bfb0e92b7a5a581cc18afab1a36848dad72d37a6a0be5698533dff11a014026ab5521c51581c1e44710275537a2f905e369ad37754afb36e1cfedfe5ca6c198e9cc6581c3bfaa6703f4d78efdf03dbae43d88ea9b309be0f66ed38a7008c2eb1ffd8799f1a000f42401a000f42401a000f4240ff581cb2f24e2ec2bfd520646fcec685cd8c1eb3e8272da30d8311fd397678d8799f581ce4d33c4f86ac40278cdd80572abfa7e91b01fbba68d8fa258bf7ef46581c916c03c8f98c44a176de6660e6e45ac0cd59aa4fe6c332bed1e8d79d9f4444618a674445b555bd444cae2fd24457d8ea10445f3a83b8446aa8bd5d44726aaa90448be2ee9c448c4234e844d05fd9e244ecf39067440892f565440c55ccd7443d4d980744520fc569445c99b6b44463e2123b4478820b6c44a16af81444ad997a9244e7982636ff581c47f7fbe11f6d176632a4d73a5a0be81810c4918281f55df0d3485685ffd8799f581cb07d22a4dc75abdba1b8c80033a15b85305b76521a0114b17f291a87581c362e3f869c98ce971ead0e2705c56df467ddd2aecb44f6f216c3e1d54a4f7261636c6546656564581c769c4c6e9bc3ba5406b9b89fb7beb6819e638ff2e2de63f008d5bcff45744e45574d1b000000746a528800ffff82581d60f4a78bbff6d5e7e492915986abc495382247af659018451a25cec92c1a11c8a0d31082581d60f4a78bbff6d5e7e492915986abc495382247af659018451a25cec92c1a00431d9c111a00092da4021a00061e6d0ed9010285581c10a20db9464d89dab407b3397e67facf83db8d442e601b627c0a351f581c121ce13907d40c7a598d182ed751d39279cf30d50decb17151b3a587581cc59da4ec6e515c2efc8866274dee6ac9a64b5945efd365f3a999e760581cd858ecf3e73e18bef8383a16e856778e033cfd1c8867c70dc9b68b42581cf4a78bbff6d5e7e492915986abc495382247af659018451a25cec92c0b5820cc1eb6b650d646141719844845959d0e14ca1087be4663af6b63973b89688a50a105a182000082d87980821a000c4f8c1a0da69936f5f6";

    /// Koios epoch_params, mainnet epoch 511, PlutusV3. Kept offline so this
    /// regression test never relies on the network.
    const EPOCH_511_PLUTUS_V3: &[i64] = &[
        100788, 420, 1, 1, 1000, 173, 0, 1, 1000, 59957, 4, 1, 11183, 32, 201305, 8356, 4, 16000,
        100, 16000, 100, 16000, 100, 16000, 100, 16000, 100, 16000, 100, 100, 100, 16000, 100,
        94375, 32, 132994, 32, 61462, 4, 72010, 178, 0, 1, 22151, 32, 91189, 769, 4, 2, 85848,
        123203, 7305, -900, 1716, 549, 57, 85848, 0, 1, 1, 1000, 42921, 4, 2, 24548, 29498, 38, 1,
        898148, 27279, 1, 51775, 558, 1, 39184, 1000, 60594, 1, 141895, 32, 83150, 32, 15299, 32,
        76049, 1, 13169, 4, 22100, 10, 28999, 74, 1, 28999, 74, 1, 43285, 552, 1, 44749, 541, 1,
        33852, 32, 68246, 32, 72362, 32, 7243, 32, 7391, 32, 11546, 32, 85848, 123203, 7305, -900,
        1716, 549, 57, 85848, 0, 1, 90434, 519, 0, 1, 74433, 32, 85848, 123203, 7305, -900, 1716,
        549, 57, 85848, 0, 1, 1, 85848, 123203, 7305, -900, 1716, 549, 57, 85848, 0, 1, 955506,
        213312, 0, 2, 270652, 22588, 4, 1457325, 64566, 4, 20467, 1, 4, 0, 141992, 32, 100788, 420,
        1, 1, 81663, 32, 59498, 32, 20142, 32, 24588, 32, 20744, 32, 25933, 32, 24623, 32,
        43053543, 10, 53384111, 14333, 10, 43574283, 26308, 10, 16000, 100, 16000, 100, 962335, 18,
        2780678, 6, 442008, 1, 52538055, 3756, 18, 267929, 18, 76433006, 8868, 18, 52948122, 18,
        1995836, 36, 3227919, 12, 901022, 1, 166917843, 4307, 36, 284546, 36, 158221314, 26549, 36,
        74698472, 36, 333849714, 1, 254006273, 72, 2174038, 72, 2261318, 64571, 4, 207616, 8310, 4,
        1293828, 28716, 63, 0, 1, 1006041, 43623, 251, 0, 1,
    ];

    fn models(entries: &[(u8, &[i64])]) -> CostModels {
        entries
            .iter()
            .map(|(language, costs)| (*language, costs.to_vec()))
            .collect()
    }

    fn decode(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).expect("test fixture is hex")
    }

    /// Mirror of the Python tests' `_raw_tx` helper.
    fn raw_tx(committed_hash: &str, redeemers: &str, datums: Option<&str>) -> String {
        let witnesses = match datums {
            None => format!("a105{redeemers}"),
            Some(datums) => format!("a204{datums}05{redeemers}"),
        };
        format!("84a10b5820{committed_hash}{witnesses}f5f6")
    }

    #[test]
    fn pycardano_single_language_vectors() {
        // Generated independently with PyCardano 0.13.2 using a RedeemerMap.
        let vectors: [(CostModels, &str, &str); 3] = [
            (
                models(&[(0, &[1, -2, 300])]),
                "a14100479f012119012cff",
                "d90ffb596608abad7398c9f529bda6d2c5903e0156a4eb13173f1f3abab5484b",
            ),
            (
                models(&[(1, &[4, 5])]),
                "a101820405",
                "15758bfcb99eb7bf33d7c724b27f04f2fc47a7a1ef82ca7f1b9b6b3f6299c794",
            ),
            (
                models(&[(2, &[-900, 7])]),
                "a1028239038307",
                "24df0ff8e5b7649b50dab9c366235e57c7883e3f302a08f2cff9db9e381b9601",
            ),
        ];
        for (cost_models, expected_views, expected_hash) in vectors {
            let views = encode_language_views(&cost_models).expect("valid models");
            assert_eq!(hex::encode(&views), expected_views);
            let hash = calculate_script_data_hash(&decode(REDEEMER_HEX), b"", &cost_models)
                .expect("valid models");
            assert_eq!(hex::encode(hash), expected_hash);
        }
    }

    #[test]
    fn mixed_models_use_ledger_shortlex_order() {
        let cost_models = models(&[(0, &[1]), (1, &[2]), (2, &[3])]);
        assert_eq!(
            hex::encode(encode_language_views(&cost_models).expect("valid models")),
            "a30181020281034100439f01ff",
        );
        assert_eq!(
            hex::encode(
                calculate_script_data_hash(&decode(REDEEMER_HEX), b"", &cost_models)
                    .expect("valid models")
            ),
            "0073264c2b07c0e1dca8da819ba6cf9e43f181ca6acfc3a4d1306469c5423ffd",
        );
    }

    #[test]
    fn all_four_languages_place_v1_last() {
        let cost_models = models(&[(0, &[1]), (1, &[2]), (2, &[3]), (3, &[4])]);
        assert_eq!(
            hex::encode(encode_language_views(&cost_models).expect("valid models")),
            "a40181020281030381044100439f01ff",
        );
        assert_eq!(
            hex::encode(
                calculate_script_data_hash(&decode(REDEEMER_HEX), b"", &cost_models)
                    .expect("valid models")
            ),
            "3adb80c4c08ede3717d7620cf890410ad2fcffdc90c1413ef4489c8a9afc9464",
        );
    }

    #[test]
    fn real_accepted_mainnet_transaction_matches_historical_model() {
        let (committed, redeemers, datums) =
            script_data_parts(MAINNET_TX_HEX).expect("fixture parses");
        assert_eq!(
            hex::encode(&committed),
            "cc1eb6b650d646141719844845959d0e14ca1087be4663af6b63973b89688a50"
        );
        assert_eq!(
            hex::encode(&redeemers),
            "a182000082d87980821a000c4f8c1a0da69936"
        );
        assert!(datums.is_empty());

        let v3 = models(&[(2, EPOCH_511_PLUTUS_V3)]);
        assert!(verify_script_data_hash(MAINNET_TX_HEX, &v3).expect("fixture parses"));

        // The same parameters under the wrong language id must not match.
        let wrong = models(&[(1, EPOCH_511_PLUTUS_V3)]);
        assert!(!verify_script_data_hash(MAINNET_TX_HEX, &wrong).expect("fixture parses"));

        // The matching language buried in a larger set is still found.
        let mixed = models(&[(0, &[1]), (2, EPOCH_511_PLUTUS_V3), (3, &[7, 8])]);
        assert!(verify_script_data_hash(MAINNET_TX_HEX, &mixed).expect("fixture parses"));
    }

    #[test]
    fn exact_indefinite_redeemer_bytes_are_preserved_and_bound() {
        let redeemers = "9f9f0000d87980820a14ffff";
        let cost_models = models(&[(1, &[4, 5])]);
        let committed = "c5f784e57bcc61bf2ad0bfc6318da58f85c15993f6402c7af489f328bf926aca";
        assert_eq!(
            hex::encode(
                calculate_script_data_hash(&decode(redeemers), b"", &cost_models)
                    .expect("valid models")
            ),
            committed
        );

        let tx = raw_tx(committed, redeemers, None);
        let (body_hash, extracted, datums) = script_data_parts(&tx).expect("fixture parses");
        assert_eq!(hex::encode(&body_hash), committed);
        assert_eq!(hex::encode(&extracted), redeemers);
        assert!(datums.is_empty());
        assert!(verify_script_data_hash(&tx, &cost_models).expect("fixture parses"));
    }

    #[test]
    fn redeemer_mutation_does_not_match_signed_body() {
        let cost_models = models(&[(1, &[4, 5])]);
        let committed = "15758bfcb99eb7bf33d7c724b27f04f2fc47a7a1ef82ca7f1b9b6b3f6299c794";
        let mutated = "a182000082d87980820a15";
        assert!(
            !verify_script_data_hash(&raw_tx(committed, mutated, None), &cost_models)
                .expect("fixture parses")
        );
    }

    #[test]
    fn datum_original_bytes_are_bound() {
        let datums = "81d8799f01ff";
        let cost_models = models(&[(1, &[4, 5])]);
        let committed = "b93bbe905b370f6d62ee0f95c5b54a7ead5a3a47c436363f361b90d9dc765e2f";
        assert_eq!(
            hex::encode(
                calculate_script_data_hash(&decode(REDEEMER_HEX), &decode(datums), &cost_models)
                    .expect("valid models")
            ),
            committed
        );
        assert!(verify_script_data_hash(
            &raw_tx(committed, REDEEMER_HEX, Some(datums)),
            &cost_models
        )
        .expect("fixture parses"));
        assert!(!verify_script_data_hash(
            &raw_tx(committed, REDEEMER_HEX, Some("81d8799f02ff")),
            &cost_models
        )
        .expect("fixture parses"));
    }

    #[test]
    fn present_but_empty_datum_collection_contributes_no_bytes() {
        let cost_models = models(&[(1, &[4, 5])]);
        let committed = "15758bfcb99eb7bf33d7c724b27f04f2fc47a7a1ef82ca7f1b9b6b3f6299c794";
        // Tagged set and bare list forms both decode to an empty collection.
        for empty in ["d9010280", "80", "a0"] {
            let tx = raw_tx(committed, REDEEMER_HEX, Some(empty));
            assert!(script_data_parts(&tx).expect("fixture parses").2.is_empty());
            assert!(verify_script_data_hash(&tx, &cost_models).expect("fixture parses"));
        }
        // A non-empty set still contributes its exact wire bytes.
        let tagged = "d9010281d8799f01ff";
        assert_eq!(
            hex::encode(
                script_data_parts(&raw_tx(committed, REDEEMER_HEX, Some(tagged)))
                    .expect("fixture parses")
                    .2
            ),
            tagged
        );
    }

    #[test]
    fn envelope_and_field_errors_match_python_messages() {
        let hash = "00".repeat(32);
        let body = format!("a10b5820{hash}");
        let witness = format!("a105{REDEEMER_HEX}");
        let cases: [(String, &str); 12] = [
            ("zz".to_string(), "transaction is not hexadecimal CBOR"),
            ("abc".to_string(), "transaction is not hexadecimal CBOR"),
            (String::new(), "truncated CBOR"),
            ("a0".to_string(), "expected CBOR array"),
            (
                format!("83{body}{witness}f5"),
                "transaction must have four elements",
            ),
            (
                format!("84a1f400{witness}f5f6"),
                "transaction map key is not an integer",
            ),
            (
                format!("84a20b5820{hash}0b5820{hash}{witness}f5f6"),
                "transaction map key is duplicated",
            ),
            (
                format!("84{body}a205{REDEEMER_HEX}05{REDEEMER_HEX}f5f6"),
                "transaction map key is duplicated",
            ),
            (
                format!("84{body}{witness}f5f600"),
                "transaction has trailing CBOR data",
            ),
            (
                format!("84a10b450011223344{witness}f5f6"),
                "transaction has no valid script data hash",
            ),
            (
                format!("84a0{witness}f5f6"),
                "transaction has no valid script data hash",
            ),
            (format!("84{body}a0f5f6"), "transaction has no redeemers"),
        ];
        for (tx, expected) in cases {
            let err = script_data_parts(&tx).expect_err("must be rejected");
            assert_eq!(err.to_string(), expected, "tx {tx}");
        }
    }

    #[test]
    fn indefinite_envelope_and_maps_are_accepted() {
        let hash = "00".repeat(32);
        for tx in [
            format!("9fa10b5820{hash}a105{REDEEMER_HEX}f5f6ff"),
            format!("84bf0b5820{hash}ffa105{REDEEMER_HEX}f5f6"),
            format!("84a10b5820{hash}bf05{REDEEMER_HEX}fff5f6"),
        ] {
            let (committed, redeemers, datums) =
                script_data_parts(&tx).unwrap_or_else(|err| panic!("{tx}: {err}"));
            assert_eq!(hex::encode(&committed), hash);
            assert_eq!(hex::encode(&redeemers), REDEEMER_HEX);
            assert!(datums.is_empty());
        }
    }

    #[test]
    fn truncated_witness_map_is_rejected() {
        let hash = "00".repeat(32);
        let err =
            script_data_parts(&format!("84a10b5820{hash}a105")).expect_err("must be rejected");
        assert_eq!(err.to_string(), "invalid CBOR value");
    }

    #[test]
    fn cost_model_validation_matches_python_messages() {
        assert_eq!(
            encode_language_views(&CostModels::new())
                .expect_err("empty")
                .to_string(),
            "protocol cost models are empty"
        );
        assert_eq!(
            encode_language_views(&models(&[(4, &[1])]))
                .expect_err("bad language")
                .to_string(),
            "protocol cost model language is invalid"
        );
        assert_eq!(
            encode_language_views(&models(&[(1, &[])]))
                .expect_err("empty model")
                .to_string(),
            "protocol cost model is invalid"
        );
        // Validation precedes any hashing work in the verify path too.
        let hash = "00".repeat(32);
        assert_eq!(
            verify_script_data_hash(
                &format!("84a10b5820{hash}a105{REDEEMER_HEX}f5f6"),
                &CostModels::new()
            )
            .expect_err("empty")
            .to_string(),
            "protocol cost models are empty"
        );
    }
}
