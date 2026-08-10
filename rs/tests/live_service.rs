//! End-to-end checks against a running instance.
//!
//! Everything else in this crate tests the pieces. This drives the assembled
//! binary over real HTTP: middleware ordering, the request-shape errors, the
//! `{"detail": ...}` envelope, and — when a transaction is supplied — a real
//! witness validated all the way through live phase-2 evaluation.
//!
//! It is OFF unless an instance is actually listening, because the point is to
//! test a running service rather than to fail when one is absent. Start one
//! with `./scripts/run-local.sh`, then:
//!
//! ```sh
//! COLLATERAL_BASE_URL=http://127.0.0.1:8099 cargo test --test live_service -- --nocapture
//! ```
//!
//! Skipped tests still report `ok` — libtest has no third outcome — and the
//! reason only reaches you under `--nocapture`. Treat a green line here as
//! proof of nothing unless you saw the output. `scripts/e2e.sh` always passes
//! `--nocapture` for exactly that reason.
//!
//! `scripts/e2e.sh` does the whole cycle, including building a transaction
//! that earns a real witness and passing it in via `COLLATERAL_LIVE_TX`.

use tokio::sync::OnceCell;

use collateral_provider::cbor;
use collateral_provider::signature::{blake2b, tx_id};

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8099";

/// Probe once per test binary. Liveness is the right probe: `/healthz` can
/// legitimately answer 503 on a broken signing identity, and that is a result
/// these tests should report rather than a reason to skip them.
async fn service() -> Option<&'static str> {
    static URL: OnceCell<Option<String>> = OnceCell::const_new();
    URL.get_or_init(|| async {
        let url = std::env::var("COLLATERAL_BASE_URL")
            .unwrap_or_else(|_| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();

        let probe = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .ok();
        let reachable = match probe {
            Some(client) => client.get(format!("{url}/livez")).send().await.is_ok(),
            None => false,
        };

        if reachable {
            Some(url)
        } else {
            eprintln!(
                "skipped: no collateral provider listening at {url}. \
                 Start one with ./scripts/run-local.sh, or set COLLATERAL_BASE_URL."
            );
            None
        }
    })
    .await
    .as_deref()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("http client builds")
}

/// `(status, body text)`.
async fn get(base: &str, path: &str) -> (reqwest::StatusCode, String, reqwest::header::HeaderMap) {
    let url = format!("{base}{path}");
    let response = client().get(&url).send().await.expect("request sends");
    let status = response.status();
    let headers = response.headers().clone();
    (status, response.text().await.expect("body reads"), headers)
}

/// POST a raw JSON body and return `(status, detail-or-body)`.
async fn post_json(base: &str, path: &str, body: &str) -> (reqwest::StatusCode, serde_json::Value) {
    post_with(base, path, body, "application/json").await
}

async fn post_with(
    base: &str,
    path: &str,
    body: &str,
    content_type: &str,
) -> (reqwest::StatusCode, serde_json::Value) {
    let url = format!("{base}{path}");
    let response = client()
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .body(body.to_string())
        .send()
        .await
        .expect("request sends");
    let status = response.status();
    let text = response.text().await.expect("body reads");
    let json = serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("response was not JSON ({err}): {text}"));
    (status, json)
}

fn detail(value: &serde_json::Value) -> &str {
    value["detail"]
        .as_str()
        .unwrap_or_else(|| panic!("response carried no string detail: {value}"))
}

/// Bind `base` to the running service's URL, or return from the test with a
/// printed reason when nothing is listening.
macro_rules! require_service {
    () => {
        match service().await {
            Some(url) => url,
            None => return,
        }
    };
}

// --- health and discovery -------------------------------------------------

#[tokio::test]
async fn liveness_and_readiness_answer_with_no_store() {
    let base = require_service!();

    for path in ["/livez", "/healthz"] {
        let (status, body, headers) = get(base, path).await;
        assert!(
            status.is_success(),
            "{path} answered {status}: {body} — if this is /healthz the signing \
             identity is broken, which is a real failure, not a skip"
        );
        let json: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
        assert_eq!(json["status"], "ok", "{path}");
        assert!(json["version"].is_string(), "{path} reported no version");
        // A proxy caching "ok" past the moment the keys disappear is exactly
        // the failure this header exists to prevent.
        assert_eq!(
            headers
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "{path} is cacheable"
        );
        assert!(
            headers.contains_key("x-request-id"),
            "{path} carried no request id"
        );
    }
}

#[tokio::test]
async fn a_client_request_id_is_echoed_and_a_hostile_one_is_replaced() {
    let base = require_service!();
    let url = format!("{}/livez", base);

    let echoed = client()
        .get(&url)
        .header("x-request-id", "trace-abc-123")
        .send()
        .await
        .expect("sends");
    assert_eq!(
        echoed
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("trace-abc-123")
    );

    // A value carrying a newline could forge a second log line; it must be
    // replaced outright rather than sanitised into something that could
    // collide with a legitimate caller's id.
    let forged = client()
        .get(&url)
        .header("x-request-id", "ok\u{9}WARNING forged")
        .send()
        .await;
    if let Ok(forged) = forged {
        let id = forged
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_ne!(id, "ok\u{9}WARNING forged");
        assert_eq!(id.len(), 12, "expected a freshly minted id, got {id:?}");
    }
}

#[tokio::test]
async fn known_hosts_serves_a_registry_object() {
    let base = require_service!();
    let (status, body, headers) = get(base, "/known_hosts/").await;
    assert!(status.is_success(), "{status}: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
    assert!(json.is_object(), "registry is not an object: {json}");
    assert_eq!(
        headers
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "discovery data must not be cached past a hot reload"
    );
}

#[tokio::test]
async fn unknown_paths_and_methods_use_the_detail_envelope() {
    let base = require_service!();

    let (status, body, _) = get(base, "/definitely-not-a-route").await;
    assert_eq!(status, 404, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(detail(&json), "Not Found");

    // A redirect here would be worse than an error: mainstream clients follow
    // redirects, so a mistyped collateral URL would look like a success.
    assert!(
        !status.is_redirection(),
        "an API-only service must not redirect"
    );

    let url = format!("{}/livez", base);
    let response = client().delete(&url).send().await.expect("sends");
    assert_eq!(response.status(), 405);
    // DRF quotes the verb and advertises the methods it does accept.
    assert_eq!(
        response
            .headers()
            .get("allow")
            .and_then(|value| value.to_str().ok()),
        Some("GET, HEAD, OPTIONS")
    );
    let json: serde_json::Value = response.json().await.expect("JSON");
    assert_eq!(detail(&json), "Method \"DELETE\" not allowed.");
}

// --- request shape --------------------------------------------------------

#[tokio::test]
async fn an_unknown_environment_is_rejected_before_anything_else() {
    let base = require_service!();
    let (status, json) = post_json(base, "/nosuchnetwork/collateral/", r#"{"tx":"00"}"#).await;
    assert_eq!(status, 400);
    assert_eq!(detail(&json), "Invalid Environment");
}

#[tokio::test]
async fn a_non_json_content_type_is_415() {
    let base = require_service!();
    let (status, json) =
        post_with(base, "/preprod/collateral/", r#"{"tx":"00"}"#, "text/plain").await;
    assert_eq!(status, 415, "{json}");
    // DRF names the media type it refused.
    assert_eq!(
        detail(&json),
        "Unsupported media type \"text/plain\" in request."
    );
}

#[tokio::test]
async fn a_chunked_body_without_content_length_is_411() {
    let base = require_service!();
    let url = format!("{}/preprod/collateral/", base);
    // wrap_stream forces chunked transfer encoding, so no Content-Length is
    // sent. Django bounds the request by that header, so a chunked body would
    // otherwise reach the parser empty and the caller would be told the `tx`
    // field was missing for a request they sent correctly.
    let body = reqwest::Body::wrap_stream(futures_util::stream::once(async {
        Ok::<_, std::io::Error>(bytes::Bytes::from_static(br#"{"tx":"00"}"#))
    }));
    let response = client()
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .expect("sends");
    assert_eq!(response.status(), 411);
    let json: serde_json::Value = response.json().await.expect("JSON");
    assert_eq!(detail(&json), "Content-Length Header Is Required");
}

#[tokio::test]
async fn request_shape_errors_match_the_documented_wording() {
    let base = require_service!();

    let cases: &[(&str, u16, &str)] = &[
        (r#"{}"#, 400, "Missing required field: 'tx'"),
        (r#"{"tx":null}"#, 400, "Field 'tx' may not be null"),
        (r#"{"tx":""}"#, 400, "Field 'tx' may not be blank"),
        (r#"{"tx":"   "}"#, 400, "Field 'tx' may not be blank"),
        (r#"{"tx":true}"#, 400, "tx: Not a valid string."),
        (r#"{"tx":["00"]}"#, 400, "tx: Not a valid string."),
        (
            r#"{"tx":"00","additional_utxos":[{"a":1}]}"#,
            400,
            "additional_utxos: additional_utxos is not supported; \
             submit only ledger-resolved inputs.",
        ),
        // Hex that decodes but is not a transaction, and hex that does not
        // decode at all, are distinct failures.
        (r#"{"tx":"zz"}"#, 400, "Invalid Hex Data In Tx"),
        (r#"{"tx":"00"}"#, 400, "Tx Is Not A List"),
    ];

    for (body, expected_status, expected_detail) in cases {
        let (status, json) = post_json(base, "/preprod/collateral/", body).await;
        assert_eq!(status.as_u16(), *expected_status, "for {body}: {json}");
        assert_eq!(detail(&json), *expected_detail, "for {body}");
    }
}

#[tokio::test]
async fn an_oversized_body_is_rejected_before_it_is_parsed() {
    let base = require_service!();
    // Two hex characters per byte, so this is comfortably past both the 16 KiB
    // transaction cap and the derived body cap.
    let huge = format!(r#"{{"tx":"{}"}}"#, "00".repeat(64 * 1024));
    let (status, json) = post_json(base, "/preprod/collateral/", &huge).await;
    assert_eq!(status, 413, "{json}");
    assert_eq!(detail(&json), "Request Body Too Large");
}

#[tokio::test]
async fn a_real_transaction_that_ignores_our_collateral_is_refused() {
    let base = require_service!();

    // A genuine mainnet transaction from the corpus: well-formed in every
    // structural respect, but it does not name this instance's collateral
    // UTxO, so it must be refused before any upstream call.
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
        .find(|entry| {
            entry["cbor"]
                .as_str()
                .and_then(|hex| hex::decode(hex).ok())
                .is_some_and(|bytes| bytes.len() < 8000)
        })
        .and_then(|entry| entry["cbor"].as_str())
        .expect("a transaction small enough for the body cap");

    let body = serde_json::json!({ "tx": cbor }).to_string();
    let (status, json) = post_json(base, "/preprod/collateral/", &body).await;
    assert_eq!(status, 400, "{json}");
    // Which refusal depends on the fixture's shape; all of them are local
    // structural checks that must fire before the evaluator is consulted.
    let message = detail(&json);
    assert!(
        message.contains("Collateral")
            || message.contains("Required Signers")
            || message.contains("Boolean")
            || message.contains("Four Elements"),
        "unexpected refusal: {message}"
    );
}

// --- the full path --------------------------------------------------------

/// The only test that proves the whole thing works: a transaction that passes
/// every local check, survives live phase-2 evaluation at the configured
/// evaluator, and comes back as a witness that verifies against the exact body
/// bytes the caller submitted.
///
/// Needs a transaction built for this instance's own PKH and collateral UTxO,
/// which `scripts/e2e.sh` produces. Without `COLLATERAL_LIVE_TX` it reports
/// that it was skipped rather than passing silently.
#[tokio::test]
async fn a_supplied_transaction_earns_a_verifiable_witness() {
    let base = require_service!();

    let Ok(tx) = std::env::var("COLLATERAL_LIVE_TX") else {
        eprintln!(
            "skipped: set COLLATERAL_LIVE_TX to a transaction built for this \
             instance's collateral UTxO (see scripts/e2e.sh) to exercise the \
             full signing path"
        );
        return;
    };
    let tx = tx.trim().to_string();
    let network = std::env::var("COLLATERAL_LIVE_NETWORK").unwrap_or_else(|_| "preprod".into());

    let body = serde_json::json!({ "tx": tx }).to_string();
    let (status, json) = post_json(base, &format!("/{network}/collateral/"), &body).await;
    assert_eq!(
        status, 200,
        "the supplied transaction was refused: {}",
        json
    );

    let witness_hex = json["witness"]
        .as_str()
        .unwrap_or_else(|| panic!("no witness in {json}"));
    let witness = hex::decode(witness_hex).expect("witness is hex");

    // Shape: cbor([0, [pubkey, signature]]) — Cardano's vkey witness.
    let decoded = cbor::decode_exact(&witness).expect("witness is CBOR");
    let items = decoded.as_array().expect("witness is an array");
    assert_eq!(items.len(), 2, "witness array has the wrong arity");
    assert_eq!(items[0].as_u64(), Some(0), "witness tag is not 0");
    let pair = items[1].as_array().expect("witness payload is an array");
    let public_key = pair[0].as_bytes().expect("public key bytes");
    let signature = pair[1].as_bytes().expect("signature bytes");
    assert_eq!(public_key.len(), 32);
    assert_eq!(signature.len(), 64);

    // The signature must cover blake2b256 of the body's exact wire bytes. If
    // the service re-serialized the body, this is where it shows up: the
    // transaction id would differ from the one a node computes and the
    // witness would be rejected on submit.
    let expected_id = tx_id(&tx).expect("transaction id");
    let message = hex::decode(&expected_id).expect("id is hex");

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
        &public_key.try_into().expect("32-byte public key"),
    )
    .expect("public key is on the curve");
    let signature =
        ed25519_dalek::Signature::from_bytes(&signature.try_into().expect("64-byte signature"));
    verifying_key
        .verify_strict(&message, &signature)
        .expect("witness does not verify against blake2b256 of the submitted body");

    // And the key that signed must be the identity the service advertises.
    let (_, registry, _) = get(base, "/known_hosts/").await;
    let registry: serde_json::Value = serde_json::from_str(&registry).expect("registry JSON");
    let pkh = hex::encode(blake2b(public_key, 28));
    assert!(
        registry.get(&pkh).is_some(),
        "the signing key's PKH {pkh} is not the one published at /known_hosts/"
    );

    eprintln!("witness verified for transaction {expected_id} (signed by {pkh})");
}
