//! Concurrency and contention behaviour.
//!
//! The unit suites are effectively single-threaded: they prove each piece is
//! correct in isolation. This one asks whether the pieces stay correct when
//! many requests touch them at once, which is the state the service actually
//! runs in. Everything here is local — no network, no upstream — so it can run
//! in CI alongside the rest.
//!
//! The properties that matter for a service that holds a signing key:
//!
//! - The throttle is the only abuse control. If it over-admits under
//!   contention, it is not a control.
//! - A witness must never pair a signature from one identity with the public
//!   key of another. A key rotation racing an in-flight signature is the way
//!   that would happen.
//! - An operator editing `bans.json` must never make a reader observe a torn
//!   or partially-parsed document.
//! - Nothing may deadlock or wedge: every lock here is held across work that
//!   other requests are waiting on.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use collateral_provider::cbor::{encode_array, encode_bytes, encode_head, encode_uint};
use collateral_provider::config::Config;
use collateral_provider::data_files::ReloadingJson;
use collateral_provider::signature::{blake2b, KeyCache};
use collateral_provider::state::AppState;
use collateral_provider::throttle::{Throttle, ThrottleDecision};
use collateral_provider::tx_fields::SET_TAG;

const TXID: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

/// How hard to push. Kept modest so the suite stays a few seconds in CI; the
/// races these look for reproduce readily at this width.
const WIDTH: usize = 64;

// --- fixtures ----------------------------------------------------------------

struct Identity {
    _dir: tempfile::TempDir,
    skey_path: std::path::PathBuf,
    vkey_path: std::path::PathBuf,
    pkh: String,
    public_key: [u8; 32],
}

/// A signing identity on disk, in the Cardano CLI JSON shape the loader expects.
fn identity(seed_byte: u8) -> Identity {
    let seed = [seed_byte; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public_key = signing.verifying_key().to_bytes();
    let pkh = hex::encode(blake2b(&public_key, 28));

    let dir = tempfile::tempdir().expect("temp dir");
    let skey_path = dir.path().join("payment.skey");
    let vkey_path = dir.path().join("payment.vkey");
    write_key(&skey_path, &hex::encode(seed));
    write_key(&vkey_path, &hex::encode(public_key));
    Identity {
        _dir: dir,
        skey_path,
        vkey_path,
        pkh,
        public_key,
    }
}

/// The loader strips a 4-character CBOR byte-string head.
fn write_key(path: &Path, value: &str) {
    let mut file = std::fs::File::create(path).expect("create key file");
    write!(file, "{{\"cborHex\": \"5820{value}\"}}").expect("write key file");
}

/// Replace a file atomically, the way an operator rotating keys should.
fn replace_key(path: &Path, value: &str) {
    let temp = path.with_extension("tmp");
    write_key(&temp, value);
    std::fs::rename(&temp, path).expect("atomic replace");
}

fn config_for(pkh: &str) -> Config {
    let env: std::collections::HashMap<&str, String> = [
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
    Config::from_lookup(&|key| env.get(key).cloned()).expect("config builds")
}

fn tagged_set(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = encode_head(6, SET_TAG);
    out.extend(encode_array(items));
    out
}

fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = encode_head(5, entries.len() as u64);
    for (key, value) in entries {
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }
    out
}

/// The smallest transaction that satisfies every structural validator.
fn happy_path_tx(pkh: &str) -> String {
    let inputs = tagged_set(&[encode_array(&[encode_bytes(&[0u8; 32]), encode_uint(0)])]);
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
    hex::encode(encode_array(&[body, map(&[]), vec![0xf5], vec![0xf6]]))
}

// --- the throttle ------------------------------------------------------------

#[test]
fn the_throttle_admits_exactly_its_budget_under_contention() {
    // A sliding window is a read-modify-write. If the read and the write are
    // not atomic with respect to each other, concurrent callers each see room
    // and the budget is exceeded — silently, and only under load.
    for _ in 0..8 {
        let budget = 50;
        let throttle = Arc::new(Throttle::new(
            format!("{budget}/min").parse().expect("valid rate"),
            1000,
        ));
        let admitted = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|scope| {
            for _ in 0..WIDTH {
                let throttle = Arc::clone(&throttle);
                let admitted = Arc::clone(&admitted);
                scope.spawn(move || {
                    for _ in 0..20 {
                        if matches!(throttle.allow("198.51.100.7"), ThrottleDecision::Allowed) {
                            admitted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        });

        // Exactly the budget: not "roughly", not "at most a bit over".
        assert_eq!(
            admitted.load(Ordering::Relaxed),
            budget,
            "the window admitted the wrong number of requests"
        );
    }
}

#[test]
fn distinct_identities_do_not_share_a_budget_under_contention() {
    let throttle = Arc::new(Throttle::new("1/min".parse().expect("valid rate"), 10_000));
    let admitted = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|scope| {
        for worker in 0..WIDTH {
            let throttle = Arc::clone(&throttle);
            let admitted = Arc::clone(&admitted);
            scope.spawn(move || {
                // Every worker hammers its own identity three times over.
                for _ in 0..3 {
                    for index in 0..25 {
                        let ident = format!("10.{worker}.{index}.1");
                        if matches!(throttle.allow(&ident), ThrottleDecision::Allowed) {
                            admitted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    });

    // One admission per distinct identity, no cross-talk between buckets.
    assert_eq!(admitted.load(Ordering::Relaxed), WIDTH * 25);
}

#[test]
fn the_throttle_map_stays_bounded_and_healthy_under_identity_churn() {
    // A caller behind a rotating address pool must not grow the map without
    // bound. Eviction is what keeps the process from being a memory target.
    let max_entries = 512;
    let throttle = Arc::new(Throttle::new(
        "300/min".parse().expect("valid rate"),
        max_entries,
    ));

    std::thread::scope(|scope| {
        for worker in 0..WIDTH {
            let throttle = Arc::clone(&throttle);
            scope.spawn(move || {
                for index in 0..500 {
                    throttle.allow(&format!(
                        "172.{}.{}.{}",
                        worker % 32,
                        index / 256,
                        index % 256
                    ));
                }
            });
        }
    });

    assert!(
        throttle.healthy(),
        "the throttle reported itself unhealthy after churn"
    );
    // Still serving after eviction, and still counting.
    assert!(matches!(
        throttle.allow("203.0.113.9"),
        ThrottleDecision::Allowed
    ));
}

// --- the signing path --------------------------------------------------------

#[test]
fn concurrent_signers_all_get_the_same_witness() {
    let identity = identity(0x11);
    let keys = Arc::new(KeyCache::new());
    let tx = happy_path_tx(&identity.pkh);

    let witnesses = std::sync::Mutex::new(HashSet::new());
    std::thread::scope(|scope| {
        for _ in 0..WIDTH {
            let keys = Arc::clone(&keys);
            let tx = tx.clone();
            let identity = &identity;
            let witnesses = &witnesses;
            scope.spawn(move || {
                for _ in 0..10 {
                    let (witness, tx_hash) = keys
                        .witness_tx_cbor(&tx, &identity.skey_path, &identity.pkh)
                        .expect("signs");
                    assert_eq!(tx_hash.len(), 64);
                    witnesses.lock().expect("lock").insert(witness);
                }
            });
        }
    });

    // Ed25519 is deterministic and the key never changed, so every one of the
    // 640 signatures must be byte-identical. More than one value would mean
    // the cache handed out a stale or half-written key.
    assert_eq!(witnesses.into_inner().expect("lock").len(), 1);
}

#[test]
fn a_key_rotation_racing_live_signatures_never_emits_a_mismatched_witness() {
    // The property that protects the collateral: a witness pairing a signature
    // from one identity with the public key of another is unusable, and worse,
    // indistinguishable from a valid one to a caller. `witness_tx_cbor`
    // rechecks the configured PKH against the key it actually signed with, so
    // a rotation mid-flight must produce an error, never a mismatch.
    let configured = identity(0x22);
    let other = identity(0x33);
    let tx = happy_path_tx(&configured.pkh);

    let keys = Arc::new(KeyCache::new());
    let stop = Arc::new(AtomicBool::new(false));
    let signed = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicUsize::new(0));

    let rotations = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|scope| {
        // One writer flipping the on-disk identity back and forth.
        {
            let stop = Arc::clone(&stop);
            let rotations = Arc::clone(&rotations);
            let skey = configured.skey_path.clone();
            let vkey = configured.vkey_path.clone();
            let mine = hex::encode([0x22u8; 32]);
            let theirs = hex::encode([0x33u8; 32]);
            let my_vkey = hex::encode(configured.public_key);
            let their_vkey = hex::encode(other.public_key);
            scope.spawn(move || {
                let mut flip = false;
                while !stop.load(Ordering::Relaxed) {
                    if flip {
                        replace_key(&skey, &theirs);
                        replace_key(&vkey, &their_vkey);
                    } else {
                        replace_key(&skey, &mine);
                        replace_key(&vkey, &my_vkey);
                    }
                    flip = !flip;
                    rotations.fetch_add(1, Ordering::Relaxed);
                    std::thread::yield_now();
                }
            });
        }

        // Collected so the writer keeps rotating until the signers are done —
        // setting `stop` straight after spawning would end the race before it
        // started, and every assertion below would pass vacuously.
        let mut workers = Vec::new();
        for _ in 0..WIDTH {
            let keys = Arc::clone(&keys);
            let tx = tx.clone();
            let signed = Arc::clone(&signed);
            let refused = Arc::clone(&refused);
            let skey_path = configured.skey_path.clone();
            let pkh = configured.pkh.clone();
            let expected_public_key = configured.public_key;
            workers.push(scope.spawn(move || {
                for _ in 0..40 {
                    match keys.witness_tx_cbor(&tx, &skey_path, &pkh) {
                        Ok((witness, _)) => {
                            // Whatever came back must carry the configured
                            // identity's public key — never the other one.
                            let bytes = hex::decode(&witness).expect("hex witness");
                            assert!(
                                contains(&bytes, &expected_public_key),
                                "witness carried a public key that is not the configured identity"
                            );
                            assert!(
                                !contains(&bytes, &other_public_key()),
                                "witness carried the rotated-in identity's public key"
                            );
                            signed.fetch_add(1, Ordering::Relaxed);
                        }
                        // The expected outcome while the wrong identity is on
                        // disk: refuse rather than sign with it.
                        Err(_) => {
                            refused.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }));
        }
        for worker in workers {
            worker.join().expect("signer did not panic");
        }
        stop.store(true, Ordering::Relaxed);
    });

    let signed = signed.load(Ordering::Relaxed);
    let refused = refused.load(Ordering::Relaxed);
    let rotations = rotations.load(Ordering::Relaxed);
    println!("signed={signed} refused={refused} rotations={rotations}");

    assert_eq!(signed + refused, WIDTH * 40);
    // Both outcomes have to have been observed, or the test proved nothing
    // about the race it exists to check: all-signed means the wrong identity
    // was never on disk during a signature, all-refused means the right one
    // never was.
    // Seeing both outcomes is itself the proof that the rotation landed inside
    // the signing window — a raw rotation count would only be a proxy, and a
    // scheduling-dependent one.
    assert!(signed > 0, "no signature succeeded; the race never landed");
    assert!(
        refused > 0,
        "no signature was refused; the rotation never raced a signer"
    );
    assert!(rotations > 0, "the writer never ran");
}

fn other_public_key() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32])
        .verifying_key()
        .to_bytes()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// --- operator data files -----------------------------------------------------

#[test]
fn a_file_rewritten_under_load_is_never_observed_torn() {
    // `bans.json` is replaced by an operator while requests are reading it.
    // A reader must see one whole version or another, never a partial parse
    // and never the default after a valid document has been served.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("bans.json");
    let versions: Vec<serde_json::Value> = (0..8)
        .map(|n| serde_json::json!({"addresses": [format!("{n:02x}")], "ips": []}))
        .collect();
    std::fs::write(&path, versions[0].to_string()).expect("seed");

    let file = Arc::new(ReloadingJson::new(
        path.clone(),
        serde_json::json!({"addresses": [], "ips": []}),
        None,
    ));
    // Prime it so "never the default" is a meaningful assertion.
    assert!(file.get().is_object());

    // The writer does a bounded number of replacements and then signals done;
    // the readers run until it does. Driving the race off the writer's own
    // progress rather than off elapsed time keeps this deterministic on a busy
    // or core-starved machine, where a spinning reader pool can otherwise
    // starve the writer to a couple of iterations.
    const REPLACEMENTS: usize = 200;
    const READ_CAP: usize = 200_000;

    let done = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|scope| {
        {
            let done = Arc::clone(&done);
            let path = path.clone();
            let versions = versions.clone();
            scope.spawn(move || {
                let temp = path.with_extension("tmp");
                for index in 0..REPLACEMENTS {
                    std::fs::write(&temp, versions[index % versions.len()].to_string())
                        .expect("write");
                    std::fs::rename(&temp, &path).expect("atomic replace");
                    std::thread::yield_now();
                }
                done.store(true, Ordering::Release);
            });
        }

        for _ in 0..WIDTH {
            let file = Arc::clone(&file);
            let reads = Arc::clone(&reads);
            let done = Arc::clone(&done);
            let versions = versions.clone();
            scope.spawn(move || {
                let mut seen = 0;
                while !done.load(Ordering::Acquire) && seen < READ_CAP {
                    let observed = file.get();
                    assert!(
                        versions.iter().any(|version| version == observed.as_ref()),
                        "observed a document that was never written: {observed}"
                    );
                    seen += 1;
                    reads.fetch_add(1, Ordering::Relaxed);
                    std::thread::yield_now();
                }
            });
        }
    });

    let reads = reads.load(Ordering::Relaxed);
    println!("reads={reads} writes={REPLACEMENTS}");
    // The writer's loop is bounded, so this is a fact rather than a hope.
    assert!(reads > 0, "no reader observed the file");
}

// --- the assembled service ---------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_router_stays_responsive_under_parallel_load() {
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    let identity = identity(0x44);
    let mut config = config_for(&identity.pkh);
    config.skey_path = identity.skey_path.clone();
    config.vkey_path = identity.vkey_path.clone();
    config.throttle_rate = "100000/min".parse().expect("valid rate");
    let router = collateral_provider::routes::app(AppState::new(config).expect("state builds"));

    // /healthz revalidates the signing identity cryptographically on every
    // probe — the most lock-contended read-only path in the service.
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..WIDTH {
        let router = router.clone();
        tasks.spawn(async move {
            for _ in 0..25 {
                let request = Request::builder()
                    .uri("/healthz")
                    .header(header::HOST, "127.0.0.1")
                    .body(Body::empty())
                    .expect("request builds");
                let response = router
                    .clone()
                    .oneshot(request)
                    .await
                    .expect("router responds");
                assert_eq!(response.status(), StatusCode::OK);
            }
        });
    }

    // A wedged lock shows up as a hang, not a failure, so bound the whole run.
    let all = async {
        while let Some(joined) = tasks.join_next().await {
            joined.expect("task did not panic");
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(60), all)
        .await
        .expect("the router wedged under parallel load");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_throttle_admits_its_budget_over_real_http() {
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    let identity = identity(0x55);
    let mut config = config_for(&identity.pkh);
    config.skey_path = identity.skey_path.clone();
    config.vkey_path = identity.vkey_path.clone();
    config.throttle_rate = "40/min".parse().expect("valid rate");
    let router = collateral_provider::routes::app(AppState::new(config).expect("state builds"));

    let throttled = Arc::new(AtomicUsize::new(0));
    let served = Arc::new(AtomicUsize::new(0));

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..WIDTH {
        let router = router.clone();
        let throttled = Arc::clone(&throttled);
        let served = Arc::clone(&served);
        tasks.spawn(async move {
            for _ in 0..10 {
                // Invalid hex: rejected by a validator, so no upstream call —
                // but it still passes through the throttle first.
                let body = r#"{"tx":"zz"}"#;
                let request = Request::builder()
                    .method("POST")
                    .uri("/preprod/collateral/")
                    .header(header::HOST, "127.0.0.1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, body.len())
                    .body(Body::from(body))
                    .expect("request builds");
                let response = router
                    .clone()
                    .oneshot(request)
                    .await
                    .expect("router responds");
                match response.status() {
                    StatusCode::TOO_MANY_REQUESTS => throttled.fetch_add(1, Ordering::Relaxed),
                    StatusCode::BAD_REQUEST => served.fetch_add(1, Ordering::Relaxed),
                    other => panic!("unexpected status {other}"),
                };
            }
        });
    }
    while let Some(joined) = tasks.join_next().await {
        joined.expect("task did not panic");
    }

    // Every caller shares one identity here (no ConnectInfo, so they all land
    // in the same bucket), so exactly the budget gets through.
    assert_eq!(served.load(Ordering::Relaxed), 40);
    assert_eq!(throttled.load(Ordering::Relaxed), WIDTH * 10 - 40);
}
