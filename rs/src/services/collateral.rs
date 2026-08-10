//! Orchestrator for the collateral-witnessing pipeline.
//!
//! The request parser's job is to validate the *shape* of the incoming JSON.
//! This module's job is to run the business pipeline: ban / env / CBOR /
//! inputs / outputs / collateral / signers / upstream evaluation, and — on
//! success — sign the tx body and return the witness.

use crate::config::EnvironmentConfig;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::validators::cbor::{
    check_cbor_hex, check_collateral, check_collateral_return, check_inputs, check_outputs,
    check_signers, check_tx_body,
};
use crate::validators::environment::{check_environment, check_ip_address};
use crate::validators::transaction::check_valid_tx;

/// Run the validator chain in cheap-to-expensive order; on success sign the
/// tx body and return `(witness_hex, tx_hash_hex)`.
///
/// The first failure short-circuits the rest. Order matters — the last check
/// is the only one that makes a network call:
///
/// 1. `check_ip_address` — reject banned IPs
/// 2. `check_environment` — env must be configured
/// 3. `check_cbor_hex` — hex-decodable, within `MAX_TX_SIZE`
/// 4. `check_tx_body` — `[body, witnesses, valid_bool, aux]`, `valid_bool` true
/// 5. `check_inputs` — collateral UTxO must NOT be in inputs
/// 6. `check_outputs` — no output address on the ban list
/// 7. `check_collateral` — body[13] must be exactly our collateral UTxO
/// 8. `check_collateral_return` — if body[16] exists it must pay our PKH
/// 9. `check_signers` — our PKH must be in body[14]
/// 10. `check_valid_tx` — script-data binding, cost models, phase-2 evaluation
pub async fn issue_witness(
    state: &AppState,
    tx_cbor: &str,
    environment: &str,
    env_config: &EnvironmentConfig,
    ip_address: Option<&str>,
) -> ApiResult<(String, String)> {
    tracing::debug!(target: "api", "Validating collateral transaction");

    check_ip_address(ip_address, &state.bans)?;
    check_environment(environment, &state.config.networks())?;

    let tx_bytes = check_cbor_hex(tx_cbor, state.config.max_tx_size)?;
    let body = check_tx_body(&tx_bytes)?;
    check_inputs(&body, env_config)?;
    check_outputs(&body, &state.bans)?;
    check_collateral(&body, env_config)?;
    check_collateral_return(&body, &state.config.pkh)?;
    check_signers(&body, &state.config.pkh)?;

    // Most expensive check last: it's a remote HTTP call.
    check_valid_tx(tx_cbor, environment, env_config, &state.upstream).await?;

    state
        .keys
        .witness_tx_cbor(tx_cbor, &state.config.skey_path, &state.config.pkh)
        .map_err(|err| {
            // ERROR, not WARNING: a signing identity that has gone missing or
            // stopped matching its PKH is an operator problem that should page
            // someone, not a caller mistake.
            tracing::error!(target: "api", "Signing identity became unavailable: {}", err);
            ApiError::Signing
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::tx_fields::SET_TAG;
    use axum::http::StatusCode;
    use std::collections::HashMap;
    use std::io::Write;

    const PKH: &str = "6af53ff4f054348ad825c692dd9db8f1760a8e0eacf9af9f99306513";
    const SKEY: &str = "cd8b4de1b4cfb3a67aa3a2c1a95a4cbcf27b4e05e7e2edc2fdafa2fefac0dd3f";
    const TXID: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

    /// A signing identity whose vkey and PKH are derived from `SKEY`, written
    /// into a temp dir in the Cardano CLI JSON shape the key cache expects.
    struct Identity {
        _dir: tempfile::TempDir,
        skey_path: std::path::PathBuf,
        vkey_path: std::path::PathBuf,
        pkh: String,
    }

    fn identity() -> Identity {
        let seed: [u8; 32] = hex::decode(SKEY)
            .expect("valid hex")
            .try_into()
            .expect("32 bytes");
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vkey = signing.verifying_key().to_bytes();
        let pkh = hex::encode(crate::signature::blake2b(&vkey, 28));

        let dir = tempfile::tempdir().expect("temp dir");
        let skey_path = dir.path().join("payment.skey");
        let vkey_path = dir.path().join("payment.vkey");
        for (path, value) in [
            (&skey_path, SKEY.to_string()),
            (&vkey_path, hex::encode(vkey)),
        ] {
            let mut file = std::fs::File::create(path).expect("create key file");
            // The loader strips a 4-character CBOR byte-string head.
            write!(file, "{{\"cborHex\": \"5820{value}\"}}").expect("write key file");
        }
        Identity {
            _dir: dir,
            skey_path,
            vkey_path,
            pkh,
        }
    }

    fn config(pkh: &str) -> Config {
        let env: HashMap<&str, String> = [
            ("PKH", pkh.to_string()),
            ("ENVIRONMENT", "development".to_string()),
            ("PREPROD_NETWORK", "--testnet-magic 1".to_string()),
            ("PREPROD_TXID", TXID.to_string()),
            ("PREPROD_TXIDX", "0".to_string()),
            ("MAINNET_NETWORK", "--mainnet".to_string()),
            ("MAINNET_TXID", "b2".repeat(32)),
            ("MAINNET_TXIDX", "1".to_string()),
        ]
        .into_iter()
        .collect();
        Config::from_lookup(&|key| env.get(key).cloned()).expect("test config builds")
    }

    fn state_with(config: Config) -> AppState {
        AppState::new(config).expect("state builds")
    }

    /// A ban list file holding exactly these IPs.
    fn banned_ip_state(ip: &str) -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bans.json");
        std::fs::write(
            &path,
            serde_json::json!({"addresses": [], "ips": [ip]}).to_string(),
        )
        .expect("write bans");
        let mut config = config(PKH);
        config.bans_path = path;
        (dir, state_with(config))
    }

    fn tagged_set(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = crate::cbor::encode_head(6, SET_TAG);
        out.extend(crate::cbor::encode_array(items));
        out
    }

    fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut out = crate::cbor::encode_head(5, entries.len() as u64);
        for (key, value) in entries {
            out.extend_from_slice(key);
            out.extend_from_slice(value);
        }
        out
    }

    /// The smallest tx CBOR that satisfies every structural validator,
    /// mirroring `build_happy_path_tx_cbor` in the Python test suite.
    fn happy_path_tx(pkh: &str) -> String {
        use crate::cbor::{encode_array, encode_bytes, encode_uint};

        let inputs = tagged_set(&[encode_array(&[encode_bytes(&[0u8; 32]), encode_uint(0)])]);
        // Shelley enterprise address: header 0x60 plus a 28-byte payment hash.
        let mut address = vec![0x60u8];
        address.extend_from_slice(&[0xabu8; 28]);
        let outputs = encode_array(&[encode_array(&[
            encode_bytes(&address),
            encode_uint(5_000_000),
        ])]);
        let collateral = tagged_set(&[encode_array(&[
            encode_bytes(&hex::decode(TXID).expect("valid hex")),
            encode_uint(0),
        ])]);
        let signers = tagged_set(&[encode_bytes(&hex::decode(pkh).expect("valid hex"))]);

        let body = map(&[
            (encode_uint(0), inputs),
            (encode_uint(1), outputs),
            (encode_uint(13), collateral),
            (encode_uint(14), signers),
        ]);
        // Empty witness set, is_valid = true, no auxiliary data.
        let tx = encode_array(&[body, map(&[]), vec![0xf5], vec![0xf6]]);
        hex::encode(tx)
    }

    #[tokio::test]
    async fn banned_ip_is_rejected_before_anything_else() {
        let (_dir, state) = banned_ip_state("198.51.100.242");
        let env_config = state
            .config
            .environment("preprod")
            .expect("preprod")
            .clone();
        // The CBOR is junk; the ban must fire first regardless.
        let err = issue_witness(
            &state,
            "not-hex",
            "preprod",
            &env_config,
            Some("198.51.100.242"),
        )
        .await
        .expect_err("banned");
        assert_eq!(err.detail(), "Client IP Is Banned");
    }

    #[tokio::test]
    async fn unknown_environment_is_rejected_before_the_cbor_is_parsed() {
        let state = state_with(config(PKH));
        let env_config = state
            .config
            .environment("preprod")
            .expect("preprod")
            .clone();
        let err = issue_witness(&state, "not-hex", "fakenet", &env_config, None)
            .await
            .expect_err("bad env");
        assert_eq!(err.detail(), "Invalid Environment: fakenet");
    }

    #[tokio::test]
    async fn non_hex_tx_is_rejected() {
        let state = state_with(config(PKH));
        let env_config = state
            .config
            .environment("preprod")
            .expect("preprod")
            .clone();
        let err = issue_witness(&state, "not-hex", "preprod", &env_config, None)
            .await
            .expect_err("bad hex");
        assert_eq!(err.detail(), "Invalid Hex Data In Tx");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn structural_failures_short_circuit_before_the_upstream_call() {
        let state = state_with(config(PKH));
        let env_config = state
            .config
            .environment("preprod")
            .expect("preprod")
            .clone();
        // Our PKH is not in required signers, so check_signers fires. Reaching
        // the upstream would hang on a real network call in a unit test; the
        // fact that this returns promptly with a 400 is the assertion.
        let tx = happy_path_tx(&"cd".repeat(28));
        let err = issue_witness(&state, &tx, "preprod", &env_config, None)
            .await
            .expect_err("missing signer");
        assert_eq!(err.detail(), "Collateral Public Key Hash Is Not Being Used");
    }

    #[tokio::test]
    async fn a_broken_signing_identity_becomes_a_503() {
        // Every structural check passes and the upstream check is bypassed by
        // calling the signing step directly with a key path that does not
        // exist — the same failure mode a mid-flight key deletion produces.
        let identity = identity();
        let mut cfg = config(&identity.pkh);
        cfg.skey_path = identity.skey_path.with_extension("gone");
        cfg.vkey_path = identity.vkey_path.clone();
        let state = state_with(cfg);

        let err = state
            .keys
            .witness_tx_cbor(
                &happy_path_tx(&identity.pkh),
                &state.config.skey_path,
                &state.config.pkh,
            )
            .map_err(|err| {
                tracing::error!(target: "api", "Signing identity became unavailable: {}", err);
                ApiError::Signing
            })
            .expect_err("missing key");
        assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.detail(), "Signing Service Unavailable");
    }

    #[tokio::test]
    async fn signing_produces_a_vkey_witness_for_a_valid_identity() {
        let identity = identity();
        let mut cfg = config(&identity.pkh);
        cfg.skey_path = identity.skey_path.clone();
        cfg.vkey_path = identity.vkey_path.clone();
        let state = state_with(cfg);

        let tx = happy_path_tx(&identity.pkh);
        let (witness, tx_hash) = state
            .keys
            .witness_tx_cbor(&tx, &state.config.skey_path, &state.config.pkh)
            .expect("signs");
        assert_eq!(tx_hash.len(), 64);
        // `[0, [pubkey(32), signature(64)]]`.
        let bytes = hex::decode(&witness).expect("hex witness");
        let (value, _) = crate::cbor::decode_one(&bytes).expect("valid cbor");
        let items = value.as_array().expect("array");
        assert_eq!(items.len(), 2);
        assert!(matches!(items[0], crate::cbor::Value::Int(0)));
    }
}
