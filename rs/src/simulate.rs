//! The Koios/Ogmios upstream client.
//!
//! Two operations: fetch current Plutus cost models
//! (`queryLedgerState/protocolParameters`) and run phase-2 script evaluation
//! (`evaluateTransaction`). Both fail closed — every transport, size,
//! JSON-RPC, or schema ambiguity becomes an upstream error the caller turns
//! into a 503, distinct from a correlated transaction-invalid verdict, which
//! becomes a 400.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::config::EnvironmentConfig;
use crate::metrics::Metrics;
use crate::script_integrity::CostModels;

/// Connect quickly, fail quickly. Koios responds in well under a second on the
/// happy path; anything beyond a few seconds is the user waiting for a 502.
pub const EVALUATE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const EVALUATE_READ_TIMEOUT: Duration = Duration::from_secs(5);
pub const PROTOCOL_PARAMETERS_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const PROTOCOL_PARAMETERS_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub const PROTOCOL_PARAMETERS_MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const EVALUATION_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const PROTOCOL_COST_MODELS_CACHE: Duration = Duration::from_secs(300);

const EVALUATE_METHOD: &str = "evaluateTransaction";
const PROTOCOL_PARAMETERS_METHOD: &str = "queryLedgerState/protocolParameters";

/// Ledger language ids, matching `script_integrity`'s `CostModels` keys.
const PLUTUS_LANGUAGES: &[(&str, u8)] = &[
    ("plutus:v1", 0),
    ("plutus:v2", 1),
    ("plutus:v3", 2),
    ("plutus:v4", 3),
];

/// A cost model longer than this is not a cost model we can encode into a
/// language view, and an unbounded list is an allocation vector.
const MAX_COST_MODEL_PARAMETERS: usize = 1024;

/// The evaluate endpoint could not be reached or returned something that
/// isn't a real verdict on the submitted transaction (network failure, 5xx,
/// non-JSON body, mismatched JSON-RPC envelope).
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct UpstreamUnavailable(pub String);

/// Ogmios could not provide trustworthy current Plutus cost models.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct ProtocolParametersUnavailable(pub String);

/// Cache identity is `(environment, URL)`: repointing an environment at a
/// different evaluator must not serve the previous node's cost models.
type CacheKey = (String, String);

#[derive(Default)]
struct CostModelCache {
    /// Key to `(expiry, models)`.
    entries: HashMap<CacheKey, (Instant, CostModels)>,
    /// Keys with an upstream refresh in flight right now.
    refreshing: HashSet<CacheKey>,
}

impl CostModelCache {
    fn fresh(&self, key: &CacheKey) -> Option<CostModels> {
        let (expiry, models) = self.entries.get(key)?;
        // Cloned, so a caller mutating what it got back cannot poison the
        // cache for every later request.
        (*expiry > Instant::now()).then(|| models.clone())
    }
}

pub struct Upstream {
    client: reqwest::Client,
    /// Separate client so protocol-parameter lookups keep their shorter
    /// connect budget; reqwest fixes timeouts per client, not per request.
    params_client: reqwest::Client,
    slots: Arc<tokio::sync::Semaphore>,
    metrics: Arc<Metrics>,
    cost_models: Mutex<CostModelCache>,
    /// Woken whenever a key leaves `refreshing`, successfully or not.
    cost_models_ready: tokio::sync::Notify,
    /// How long a follower waits for the in-flight refresh before failing
    /// closed. Long enough to cover the leader's whole upstream budget.
    refresh_wait: Duration,
}

/// How a single upstream round trip failed before any verdict was available.
enum CallFailure {
    TooLarge,
    Timeout,
    Request(reqwest::Error),
}

/// Removes the single-flight marker and wakes followers even if the leader's
/// future is dropped mid-refresh; a stuck marker would wedge the key until
/// process restart.
struct RefreshGuard<'a> {
    upstream: &'a Upstream,
    key: CacheKey,
}

impl Drop for RefreshGuard<'_> {
    fn drop(&mut self) {
        self.upstream.lock_cache().refreshing.remove(&self.key);
        self.upstream.cost_models_ready.notify_waiters();
    }
}

impl Upstream {
    /// `max_in_flight` is an admission budget, not a connection-pool size: a
    /// pool is not an admission limit, and slow upstream calls must not pin
    /// every server task and starve local health/error responses. Requests
    /// above the budget fail fast rather than queueing.
    pub fn new(max_in_flight: usize, metrics: Arc<Metrics>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: build_client(EVALUATE_CONNECT_TIMEOUT, EVALUATE_READ_TIMEOUT)?,
            params_client: build_client(
                PROTOCOL_PARAMETERS_CONNECT_TIMEOUT,
                PROTOCOL_PARAMETERS_READ_TIMEOUT,
            )?,
            slots: Arc::new(tokio::sync::Semaphore::new(max_in_flight)),
            metrics,
            cost_models: Mutex::new(CostModelCache::default()),
            cost_models_ready: tokio::sync::Notify::new(),
            refresh_wait: PROTOCOL_PARAMETERS_CONNECT_TIMEOUT
                + PROTOCOL_PARAMETERS_READ_TIMEOUT
                + Duration::from_secs(1),
        })
    }

    /// Return current cost models with one in-flight refresh per cache key.
    ///
    /// A cold cache or five-minute expiry can be reached by every in-flight
    /// request at once. One task performs the upstream query while peers wait
    /// for that exact `(environment, URL)` refresh, preventing a periodic
    /// request burst from consuming the entire upstream admission budget.
    pub async fn get_protocol_cost_models(
        &self,
        environment: &str,
        env_config: &EnvironmentConfig,
    ) -> Result<CostModels, ProtocolParametersUnavailable> {
        let key = (environment.to_string(), env_config.koios_url.clone());

        let follower = {
            let mut cache = self.lock_cache();
            if let Some(models) = cache.fresh(&key) {
                return Ok(models);
            }
            // Claiming leadership under the same lock that observed the miss
            // is what makes this single-flight rather than best-effort.
            !cache.refreshing.insert(key.clone())
        };
        if follower {
            return self.await_refresh(&key, environment).await;
        }

        let _leader = RefreshGuard {
            upstream: self,
            key: key.clone(),
        };
        self.fetch_protocol_cost_models(environment, env_config, &key)
            .await
    }

    /// Submit the tx CBOR for script-evaluation simulation and return the
    /// parsed JSON-RPC response. The caller decides whether the response
    /// represents a valid tx (presence of `result`) or an invalid one
    /// (`error`).
    ///
    /// Koios may report a tx-level error as either `200 + {"error": ...}` or
    /// `4xx + {"error": ...}` depending on the failure. Both are accepted as
    /// real verdicts so a bad transaction isn't misclassified as an upstream
    /// outage. Only network errors, timeouts, unexpected statuses, oversized
    /// bodies, and non-JSON bodies become [`UpstreamUnavailable`].
    ///
    /// Caller-supplied UTxOs are never forwarded: an unsubmitted parent's
    /// output cannot be authenticated from a transaction reference alone.
    pub async fn evaluate_transaction(
        &self,
        tx_cbor_hex: &str,
        environment: &str,
        env_config: &EnvironmentConfig,
    ) -> Result<Value, UpstreamUnavailable> {
        // Correlate the response to this exact request. Koios/Ogmios echoes
        // JSON-RPC ids, which lets us reject a stale, cached, or otherwise
        // mismatched verdict instead of treating it as authority to sign.
        let request_id = new_rpc_id();
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": EVALUATE_METHOD,
            "params": {"transaction": {"cbor": tx_cbor_hex}},
        });

        let started = Instant::now();
        let Some(permit) = self.acquire_slot(environment, "evaluate") else {
            return Err(UpstreamUnavailable(format!(
                "koios {environment} is at local capacity"
            )));
        };
        let call = call_upstream(
            &self.client,
            &env_config.koios_url,
            &payload,
            EVALUATION_MAX_RESPONSE_BYTES,
            is_verdict_status,
        )
        .await;
        drop(permit);

        self.observe_duration(environment, started);
        let (status, body) = match call {
            Ok(response) => response,
            Err(CallFailure::TooLarge) => {
                self.count(environment, "malformed");
                tracing::warn!("Koios evaluation response was oversized for {environment}");
                return Err(UpstreamUnavailable(format!(
                    "koios {environment} returned an oversized evaluation response"
                )));
            }
            Err(CallFailure::Timeout) => {
                self.count(environment, "timeout");
                tracing::warn!("Koios timeout for {environment}");
                return Err(UpstreamUnavailable(format!(
                    "koios {environment} timed out"
                )));
            }
            Err(CallFailure::Request(error)) => {
                self.count(environment, "request_error");
                tracing::warn!("Koios request failed for {environment}: {error}");
                return Err(UpstreamUnavailable(format!(
                    "koios {environment} request failed"
                )));
            }
        };

        // Only the transaction-verdict statuses used by Koios are accepted
        // here. Redirects, auth failures, missing endpoints, and rate limiting
        // are service/configuration failures — not evidence that the user's tx
        // is bad.
        if !is_verdict_status(status) {
            self.count(environment, "http_error");
            tracing::warn!("Koios returned {status} for {environment}");
            return Err(UpstreamUnavailable(format!(
                "koios {environment} returned {status}"
            )));
        }

        // Successful HTTP responses plus Koios's documented 400/422 verdict
        // statuses must carry JSON. Anything unparsable is an upstream failure.
        let body: Value = match serde_json::from_slice(&body) {
            Ok(body) => body,
            Err(error) => {
                self.count(environment, "invalid_json");
                tracing::warn!(
                    "Koios returned non-JSON (status={status}) for {environment}: {error}"
                );
                return Err(UpstreamUnavailable(format!(
                    "koios {environment} returned invalid json (status {status})"
                )));
            }
        };

        if !evaluation_envelope_is_valid(&body, &request_id) {
            self.count(environment, "malformed");
            tracing::warn!("Koios returned a mismatched JSON-RPC response for {environment}");
            return Err(UpstreamUnavailable(format!(
                "koios {environment} returned a mismatched JSON-RPC response"
            )));
        }

        let outcome = if body.get("result").is_some() {
            "success"
        } else {
            "tx_invalid"
        };
        self.count(environment, outcome);
        Ok(body)
    }

    /// Clear the small process-local cost-model cache (deterministic tests).
    pub fn clear_cost_model_cache(&self) {
        {
            let mut cache = self.lock_cache();
            cache.entries.clear();
            cache.refreshing.clear();
        }
        self.cost_models_ready.notify_waiters();
    }

    /// Wait for the leader's refresh of `key`, then read what it produced.
    async fn await_refresh(
        &self,
        key: &CacheKey,
        environment: &str,
    ) -> Result<CostModels, ProtocolParametersUnavailable> {
        let deadline = Instant::now() + self.refresh_wait;
        loop {
            // Registered before the lock is released, so a refresh that
            // finishes in the gap still wakes this waiter.
            let notified = self.cost_models_ready.notified();
            tokio::pin!(notified);
            {
                let cache = self.lock_cache();
                if !cache.refreshing.contains(key) {
                    return match cache.fresh(key) {
                        Some(models) => Ok(models),
                        // The leader failed. Failing closed here rather than
                        // starting another refresh keeps a burst of followers
                        // from becoming a burst of upstream calls.
                        None => Err(ProtocolParametersUnavailable(format!(
                            "ogmios {environment} protocol parameters refresh failed"
                        ))),
                    };
                }
                notified.as_mut().enable();
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || tokio::time::timeout(remaining, notified).await.is_err() {
                return Err(ProtocolParametersUnavailable(format!(
                    "ogmios {environment} protocol parameters refresh timed out"
                )));
            }
        }
    }

    /// Query the current node protocol parameters for Plutus cost models.
    ///
    /// Script-data hashes commit to the language-specific cost models. This
    /// lookup uses the same Ogmios endpoint as transaction evaluation and
    /// fails closed on every transport, JSON-RPC, or schema ambiguity.
    async fn fetch_protocol_cost_models(
        &self,
        environment: &str,
        env_config: &EnvironmentConfig,
        key: &CacheKey,
    ) -> Result<CostModels, ProtocolParametersUnavailable> {
        let request_id = new_rpc_id();
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": PROTOCOL_PARAMETERS_METHOD,
        });

        let started = Instant::now();
        let Some(permit) = self.acquire_slot(environment, "protocol_parameters") else {
            return Err(ProtocolParametersUnavailable(format!(
                "koios {environment} is at local capacity"
            )));
        };
        let call = call_upstream(
            &self.params_client,
            &env_config.koios_url,
            &payload,
            PROTOCOL_PARAMETERS_MAX_RESPONSE_BYTES,
            |status| status == 200,
        )
        .await;
        drop(permit);

        self.observe_duration(environment, started);
        let (status, body) = match call {
            Ok(response) => response,
            Err(CallFailure::TooLarge) => {
                self.count(environment, "protocol_params_malformed");
                tracing::warn!(
                    "Ogmios protocol parameters response was oversized for {environment}"
                );
                return Err(ProtocolParametersUnavailable(format!(
                    "ogmios {environment} protocol parameters response was oversized"
                )));
            }
            Err(CallFailure::Timeout) => {
                self.count(environment, "protocol_params_timeout");
                tracing::warn!("Ogmios protocol parameters timed out for {environment}");
                return Err(ProtocolParametersUnavailable(format!(
                    "ogmios {environment} protocol parameters timed out"
                )));
            }
            Err(CallFailure::Request(error)) => {
                self.count(environment, "protocol_params_request_error");
                tracing::warn!("Ogmios protocol parameters failed for {environment}: {error}");
                return Err(ProtocolParametersUnavailable(format!(
                    "ogmios {environment} protocol parameters failed"
                )));
            }
        };

        if status != 200 {
            self.count(environment, "protocol_params_http_error");
            tracing::warn!("Ogmios protocol parameters returned {status} for {environment}");
            return Err(ProtocolParametersUnavailable(format!(
                "ogmios {environment} protocol parameters returned {status}"
            )));
        }

        let body: Value = match serde_json::from_slice(&body) {
            Ok(body) => body,
            Err(_) => {
                self.count(environment, "protocol_params_invalid_json");
                tracing::warn!(
                    "Ogmios protocol parameters returned invalid JSON for {environment}"
                );
                return Err(ProtocolParametersUnavailable(format!(
                    "ogmios {environment} protocol parameters returned invalid json"
                )));
            }
        };

        let Some(result) = protocol_parameters_result(&body, &request_id) else {
            self.count(environment, "protocol_params_malformed");
            tracing::warn!("Ogmios returned mismatched protocol parameters for {environment}");
            return Err(ProtocolParametersUnavailable(format!(
                "ogmios {environment} returned mismatched protocol parameters"
            )));
        };

        let parsed = match parse_protocol_cost_models(result) {
            Ok(parsed) => parsed,
            Err(error) => {
                self.count(environment, "protocol_params_malformed");
                tracing::warn!("Ogmios returned malformed protocol cost models for {environment}");
                return Err(error);
            }
        };

        self.lock_cache().entries.insert(
            key.clone(),
            (Instant::now() + PROTOCOL_COST_MODELS_CACHE, parsed.clone()),
        );
        self.count(environment, "protocol_params_success");
        Ok(parsed)
    }

    /// Take one admission slot without ever blocking on it.
    fn acquire_slot(
        &self,
        environment: &str,
        operation: &str,
    ) -> Option<tokio::sync::SemaphorePermit<'_>> {
        match self.slots.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                self.count(environment, "capacity");
                tracing::warn!("Koios admission budget exhausted for {environment} ({operation})");
                None
            }
        }
    }

    fn count(&self, environment: &str, outcome: &str) {
        self.metrics
            .koios_requests_total
            .with_label_values(&[environment, outcome])
            .inc();
    }

    fn observe_duration(&self, environment: &str, started: Instant) {
        self.metrics
            .koios_request_duration_seconds
            .with_label_values(&[environment])
            .observe(started.elapsed().as_secs_f64());
    }

    fn lock_cache(&self) -> MutexGuard<'_, CostModelCache> {
        // The guarded value is a plain cache; a panic elsewhere must not
        // permanently disable cost-model lookups for the whole process.
        self.cost_models
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Reuse TCP + TLS state across requests. Without pooling every call does a
/// fresh handshake — fine warm, but after an idle stretch the first request
/// pays the full setup cost, the dominant source of latency spikes that
/// surface as 504s at the platform load balancer.
fn build_client(connect: Duration, read: Duration) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        // A redirect is not a verdict, and following one would send the
        // transaction CBOR to a host the operator never configured.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect)
        .read_timeout(read)
        .pool_max_idle_per_host(16)
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
}

/// Koios reports tx-level errors with either a 2xx or one of these statuses.
fn is_verdict_status(status: u16) -> bool {
    (200..300).contains(&status) || status == 400 || status == 422
}

fn new_rpc_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// POST one JSON-RPC payload and return `(status, body)`.
///
/// The body is read only for the statuses `read_body` accepts, so an unusual
/// status costs nothing to download.
async fn call_upstream(
    client: &reqwest::Client,
    url: &str,
    payload: &Value,
    limit: usize,
    read_body: fn(u16) -> bool,
) -> Result<(u16, Vec<u8>), CallFailure> {
    let response = client
        .post(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(payload)
        .send()
        .await
        .map_err(classify)?;

    let status = response.status().as_u16();
    if !read_body(status) {
        return Ok((status, Vec::new()));
    }
    read_limited(response, limit)
        .await
        .map(|body| (status, body))
}

fn classify(error: reqwest::Error) -> CallFailure {
    if error.is_timeout() {
        CallFailure::Timeout
    } else {
        CallFailure::Request(error)
    }
}

/// Stream at most `limit` bytes from a response.
///
/// Buffering the whole body first and checking afterwards is too late: the
/// bound has to hold during the download, or a hostile or broken upstream
/// decides how much memory this process allocates.
async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, CallFailure> {
    // A declared length over the budget saves the download, but a missing or
    // malformed one is not authoritative: the streaming bound below stays the
    // source of truth.
    if let Some(declared) = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        if declared > limit as u64 {
            return Err(CallFailure::TooLarge);
        }
    }

    let mut body: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > limit {
                    return Err(CallFailure::TooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(error) => return Err(classify(error)),
        }
    }
}

/// A correlated `evaluateTransaction` reply carrying exactly one verdict.
fn evaluation_envelope_is_valid(body: &Value, request_id: &str) -> bool {
    let Some(body) = body.as_object() else {
        return false;
    };
    body.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && body.get("id").and_then(Value::as_str) == Some(request_id)
        && body.get("method").and_then(Value::as_str) == Some(EVALUATE_METHOD)
        // Exactly one of the two: a reply carrying both, or neither, is not a
        // verdict we can act on.
        && (body.contains_key("result") != body.contains_key("error"))
}

/// The `result` object of a correlated protocol-parameters reply, if any.
fn protocol_parameters_result<'a>(body: &'a Value, request_id: &str) -> Option<&'a Value> {
    let body = body.as_object()?;
    if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || body.get("id").and_then(Value::as_str) != Some(request_id)
        || body.get("method").and_then(Value::as_str) != Some(PROTOCOL_PARAMETERS_METHOD)
        || body.contains_key("error")
    {
        return None;
    }
    let result = body.get("result")?;
    result.is_object().then_some(result)
}

/// Map Ogmios's `plutusCostModels` object onto language ids.
///
/// A hard fork that introduces a language beyond `plutus:v4` would otherwise
/// take the whole service down: rejecting the entire set turns every request
/// into a 503, including transactions using only languages we do understand.
/// Skip what we cannot encode and fail only when nothing usable remains. A
/// transaction that genuinely needs the unknown language still fails its
/// script-data-hash check, which is a rejected transaction rather than a
/// scheduled outage.
pub fn parse_protocol_cost_models(
    body: &Value,
) -> Result<CostModels, ProtocolParametersUnavailable> {
    let Some(body) = body.as_object() else {
        return Err(ProtocolParametersUnavailable(
            "protocol parameters response is not an object".to_string(),
        ));
    };
    let models = match body.get("plutusCostModels").and_then(Value::as_object) {
        Some(models) if !models.is_empty() => models,
        _ => {
            return Err(ProtocolParametersUnavailable(
                "protocol cost models are missing".to_string(),
            ))
        }
    };

    let mut unknown: Vec<&str> = models
        .keys()
        .filter(|name| language_id(name).is_none())
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        unknown.sort_unstable();
        tracing::warn!(
            "Ignoring unknown Plutus cost model languages: {}",
            unknown.join(", ")
        );
    }

    let mut parsed = CostModels::new();
    for (name, parameters) in models {
        let Some(language) = language_id(name) else {
            continue;
        };
        let malformed =
            || ProtocolParametersUnavailable("protocol cost model is malformed".to_string());
        let parameters = parameters.as_array().ok_or_else(malformed)?;
        if parameters.is_empty() || parameters.len() > MAX_COST_MODEL_PARAMETERS {
            return Err(malformed());
        }

        let mut normalized = Vec::with_capacity(parameters.len());
        for parameter in parameters {
            // `as_i64` rejects booleans, floats (including integral ones like
            // `1.0`), and anything outside the signed 64-bit range the ledger
            // encoding uses.
            let Some(value) = parameter.as_i64() else {
                return Err(ProtocolParametersUnavailable(
                    "protocol cost model parameter is malformed".to_string(),
                ));
            };
            normalized.push(value);
        }
        parsed.insert(language, normalized);
    }

    if parsed.is_empty() {
        return Err(ProtocolParametersUnavailable(
            "no known protocol cost model languages".to_string(),
        ));
    }
    Ok(parsed)
}

fn language_id(name: &str) -> Option<u8> {
    PLUTUS_LANGUAGES
        .iter()
        .find(|(language, _)| *language == name)
        .map(|(_, id)| *id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RPC_ID: &str = "0123456789abcdef0123456789abcdef";

    fn upstream(max_in_flight: usize) -> Upstream {
        Upstream::new(max_in_flight, Arc::new(Metrics::new().expect("metrics")))
            .expect("client builds")
    }

    fn env_config(url: &str) -> EnvironmentConfig {
        EnvironmentConfig {
            network: "--testnet-magic 1".to_string(),
            txid: "00".repeat(32),
            txidx: 0,
            koios_url: url.to_string(),
        }
    }

    fn models(value: Value) -> Result<CostModels, ProtocolParametersUnavailable> {
        parse_protocol_cost_models(&json!({ "plutusCostModels": value }))
    }

    // parse_protocol_cost_models ------------------------------------------

    #[test]
    fn parses_every_known_language() {
        let parsed = models(json!({
            "plutus:v1": [1, 2],
            "plutus:v2": [3],
            "plutus:v3": [-900, 4],
            "plutus:v4": [i64::MIN],
        }))
        .expect("parses");
        assert_eq!(parsed.get(&0), Some(&vec![1, 2]));
        assert_eq!(parsed.get(&1), Some(&vec![3]));
        assert_eq!(parsed.get(&2), Some(&vec![-900, 4]));
        assert_eq!(parsed.get(&3), Some(&vec![i64::MIN]));
    }

    #[test]
    fn unknown_language_is_skipped_but_known_ones_survive() {
        // A hard fork shipping plutus:v5 must not become a scheduled outage.
        let parsed =
            models(json!({"plutus:v3": [1, 2, 3], "plutus:v5": [4, 5, 6]})).expect("parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.get(&2), Some(&vec![1, 2, 3]));
    }

    #[test]
    fn all_languages_unknown_fails_closed() {
        let error = models(json!({"plutus:v5": [1, 2, 3]})).expect_err("rejected");
        assert_eq!(error.0, "no known protocol cost model languages");
    }

    #[test]
    fn an_unknown_language_never_masks_a_malformed_known_one() {
        let error =
            models(json!({"plutus:v5": [1], "plutus:v3": "not-a-list"})).expect_err("rejected");
        assert_eq!(error.0, "protocol cost model is malformed");
    }

    #[test]
    fn non_object_body_is_rejected() {
        let error = parse_protocol_cost_models(&json!([])).expect_err("rejected");
        assert_eq!(error.0, "protocol parameters response is not an object");
    }

    #[test]
    fn missing_or_empty_models_are_rejected() {
        for body in [json!({}), json!({"plutusCostModels": null})] {
            let error = parse_protocol_cost_models(&body).expect_err("rejected");
            assert_eq!(error.0, "protocol cost models are missing");
        }
        let error = models(json!({})).expect_err("rejected");
        assert_eq!(error.0, "protocol cost models are missing");
    }

    #[test]
    fn malformed_model_shapes_are_rejected() {
        for value in [
            json!({"plutus:v3": []}),
            json!({"plutus:v4": "not-a-list"}),
            json!({"plutus:v3": vec![1; MAX_COST_MODEL_PARAMETERS + 1]}),
            json!({"plutus:v3": {}}),
        ] {
            let error = models(value.clone()).expect_err("rejected");
            assert_eq!(error.0, "protocol cost model is malformed", "{value}");
        }
        // The upper bound itself is still acceptable.
        assert!(models(json!({"plutus:v3": vec![1; MAX_COST_MODEL_PARAMETERS]})).is_ok());
    }

    #[test]
    fn non_integer_parameters_are_rejected() {
        // A JSON boolean is not an integer, matching Python's explicit
        // `isinstance(x, bool)` guard; nor is an integral float.
        for value in [
            json!({"plutus:v3": [true]}),
            json!({"plutus:v3": [1.0]}),
            json!({"plutus:v3": [9223372036854775808u64]}),
            json!({"plutus:v3": [null]}),
            json!({"plutus:v3": ["1"]}),
            json!({"plutus:v3": [[1]]}),
        ] {
            let error = models(value.clone()).expect_err("rejected");
            assert_eq!(
                error.0, "protocol cost model parameter is malformed",
                "{value}"
            );
        }
    }

    #[test]
    fn duplicate_language_keys_take_the_last_value() {
        // serde_json collapses duplicates last-wins, exactly like a Python
        // dict; only script_integrity rejects duplicates explicitly.
        let parsed: Value =
            serde_json::from_str(r#"{"plutusCostModels":{"plutus:v3":[1],"plutus:v3":[2]}}"#)
                .expect("valid json");
        assert_eq!(
            parse_protocol_cost_models(&parsed).expect("parses").get(&2),
            Some(&vec![2])
        );
    }

    // JSON-RPC envelope validation ----------------------------------------

    fn evaluation_reply(overrides: Value) -> Value {
        let mut body = json!({
            "jsonrpc": "2.0",
            "id": RPC_ID,
            "method": "evaluateTransaction",
            "result": [],
        });
        for (key, value) in overrides.as_object().expect("object") {
            if value.is_null() {
                body.as_object_mut().expect("object").remove(key);
            } else {
                body[key] = value.clone();
            }
        }
        body
    }

    #[test]
    fn correlated_evaluation_reply_is_accepted() {
        assert!(evaluation_envelope_is_valid(
            &evaluation_reply(json!({})),
            RPC_ID
        ));
        // An error verdict is just as correlated as a result.
        assert!(evaluation_envelope_is_valid(
            &evaluation_reply(json!({"result": null, "error": {"code": -32602}})),
            RPC_ID
        ));
    }

    #[test]
    fn mismatched_evaluation_replies_are_rejected() {
        for body in [
            json!([]),
            json!("nope"),
            evaluation_reply(json!({"id": null})),
            evaluation_reply(json!({"id": "another-request"})),
            evaluation_reply(json!({"id": 7})),
            evaluation_reply(json!({"jsonrpc": "1.0"})),
            evaluation_reply(json!({"method": "queryLedgerState/utxo"})),
            evaluation_reply(json!({"method": null})),
            // Neither verdict, and both verdicts, are equally unusable.
            evaluation_reply(json!({"result": null})),
            evaluation_reply(json!({"error": {"code": -1}})),
        ] {
            assert!(
                !evaluation_envelope_is_valid(&body, RPC_ID),
                "accepted {body}"
            );
        }
    }

    fn parameters_reply(overrides: Value) -> Value {
        let mut body = json!({
            "jsonrpc": "2.0",
            "id": RPC_ID,
            "method": "queryLedgerState/protocolParameters",
            "result": {"plutusCostModels": {"plutus:v2": [1]}},
        });
        for (key, value) in overrides.as_object().expect("object") {
            if value.is_null() {
                body.as_object_mut().expect("object").remove(key);
            } else {
                body[key] = value.clone();
            }
        }
        body
    }

    #[test]
    fn correlated_parameters_reply_yields_its_result() {
        let body = parameters_reply(json!({}));
        let result = protocol_parameters_result(&body, RPC_ID).expect("correlated");
        assert!(result.get("plutusCostModels").is_some());
    }

    #[test]
    fn mismatched_parameters_replies_are_rejected() {
        for body in [
            json!([]),
            parameters_reply(json!({"jsonrpc": "1.0"})),
            parameters_reply(json!({"id": "another-request"})),
            parameters_reply(json!({"method": "queryLedgerState/utxo"})),
            parameters_reply(json!({"error": {"code": -1}})),
            parameters_reply(json!({"result": null})),
            // A non-object result cannot carry plutusCostModels.
            parameters_reply(json!({"result": []})),
        ] {
            assert!(
                protocol_parameters_result(&body, RPC_ID).is_none(),
                "accepted {body}"
            );
        }
    }

    #[test]
    fn only_koios_verdict_statuses_are_verdicts() {
        for status in [200, 201, 299, 400, 422] {
            assert!(is_verdict_status(status), "{status}");
        }
        for status in [100, 301, 302, 401, 403, 404, 429, 500, 502, 503] {
            assert!(!is_verdict_status(status), "{status}");
        }
    }

    // Admission control and cache -----------------------------------------

    #[tokio::test]
    async fn capacity_exhaustion_fails_before_any_http_call() {
        // A zero budget means try_acquire always fails; reaching the network
        // would instead surface as a connection error to this bogus host.
        let upstream = upstream(0);
        let config = env_config("http://127.0.0.1:1/ogmios");

        let error = upstream
            .evaluate_transaction("deadbeef", "preprod", &config)
            .await
            .expect_err("no capacity");
        assert_eq!(error.0, "koios preprod is at local capacity");

        let error = upstream
            .get_protocol_cost_models("preprod", &config)
            .await
            .expect_err("no capacity");
        assert_eq!(error.0, "koios preprod is at local capacity");

        let text = upstream.metrics.gather();
        assert!(text.contains(
            "collateral_koios_requests_total{environment=\"preprod\",outcome=\"capacity\"} 2"
        ));
    }

    #[tokio::test]
    async fn a_failed_refresh_releases_the_single_flight_marker() {
        // The leader above failed on capacity; the key must not stay marked.
        let upstream = upstream(0);
        let config = env_config("http://127.0.0.1:1/ogmios");
        let key = ("preprod".to_string(), config.koios_url.clone());

        let _ = upstream.get_protocol_cost_models("preprod", &config).await;
        assert!(!upstream.lock_cache().refreshing.contains(&key));
    }

    #[tokio::test]
    async fn a_fresh_cache_entry_is_served_without_an_upstream_call() {
        let upstream = upstream(0);
        let config = env_config("http://127.0.0.1:1/ogmios");
        let key = ("preprod".to_string(), config.koios_url.clone());

        let mut cached = CostModels::new();
        cached.insert(2, vec![1, 2]);
        upstream.lock_cache().entries.insert(
            key.clone(),
            (Instant::now() + PROTOCOL_COST_MODELS_CACHE, cached.clone()),
        );

        // A zero admission budget would fail any real call.
        let mut served = upstream
            .get_protocol_cost_models("preprod", &config)
            .await
            .expect("cache hit");
        assert_eq!(served, cached);

        // Mutating the returned models must not reach the cache.
        served.insert(2, vec![999]);
        assert_eq!(
            upstream
                .get_protocol_cost_models("preprod", &config)
                .await
                .expect("cache hit"),
            cached
        );

        upstream.clear_cost_model_cache();
        assert!(upstream.lock_cache().entries.is_empty());
    }

    #[tokio::test]
    async fn an_expired_cache_entry_is_not_served() {
        let upstream = upstream(0);
        let config = env_config("http://127.0.0.1:1/ogmios");
        let key = ("preprod".to_string(), config.koios_url.clone());
        upstream
            .lock_cache()
            .entries
            .insert(key, (Instant::now(), CostModels::new()));

        let error = upstream
            .get_protocol_cost_models("preprod", &config)
            .await
            .expect_err("expired");
        assert_eq!(error.0, "koios preprod is at local capacity");
    }

    #[tokio::test]
    async fn cache_identity_includes_the_configured_url() {
        let upstream = upstream(0);
        let first = env_config("https://preprod.koios.rest/api/v1/ogmios");
        let second = env_config("https://operator.example/ogmios");

        let mut cached = CostModels::new();
        cached.insert(1, vec![1]);
        upstream.lock_cache().entries.insert(
            ("preprod".to_string(), first.koios_url.clone()),
            (Instant::now() + PROTOCOL_COST_MODELS_CACHE, cached),
        );

        assert!(upstream
            .get_protocol_cost_models("preprod", &first)
            .await
            .is_ok());
        // Repointing the environment must not serve the old node's models.
        assert!(upstream
            .get_protocol_cost_models("preprod", &second)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_follower_fails_closed_when_the_refresh_never_finishes() {
        let mut upstream = upstream(1);
        upstream.refresh_wait = Duration::from_millis(20);
        let config = env_config("http://127.0.0.1:1/ogmios");
        let key = ("preprod".to_string(), config.koios_url.clone());
        upstream.lock_cache().refreshing.insert(key);

        let error = upstream
            .get_protocol_cost_models("preprod", &config)
            .await
            .expect_err("follower gives up");
        assert_eq!(
            error.0,
            "ogmios preprod protocol parameters refresh timed out"
        );
    }

    #[tokio::test]
    async fn a_follower_reports_a_failed_leader_refresh() {
        let upstream = Arc::new({
            let mut built = upstream(1);
            built.refresh_wait = Duration::from_secs(5);
            built
        });
        let config = env_config("http://127.0.0.1:1/ogmios");
        let key = ("preprod".to_string(), config.koios_url.clone());
        upstream.lock_cache().refreshing.insert(key.clone());

        let waiter = {
            let upstream = Arc::clone(&upstream);
            let config = config.clone();
            tokio::spawn(async move { upstream.get_protocol_cost_models("preprod", &config).await })
        };

        // Give the follower time to register, then end the refresh with
        // nothing cached — exactly what a failed leader leaves behind.
        tokio::time::sleep(Duration::from_millis(50)).await;
        upstream.lock_cache().refreshing.remove(&key);
        upstream.cost_models_ready.notify_waiters();

        let error = waiter.await.expect("joined").expect_err("leader failed");
        assert_eq!(error.0, "ogmios preprod protocol parameters refresh failed");
    }

    #[tokio::test]
    async fn a_follower_returns_what_the_leader_cached() {
        let upstream = Arc::new({
            let mut built = upstream(1);
            built.refresh_wait = Duration::from_secs(5);
            built
        });
        let config = env_config("http://127.0.0.1:1/ogmios");
        let key = ("preprod".to_string(), config.koios_url.clone());
        upstream.lock_cache().refreshing.insert(key.clone());

        let waiter = {
            let upstream = Arc::clone(&upstream);
            let config = config.clone();
            tokio::spawn(async move { upstream.get_protocol_cost_models("preprod", &config).await })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut cached = CostModels::new();
        cached.insert(2, vec![1, 2]);
        {
            let mut cache = upstream.lock_cache();
            cache.entries.insert(
                key.clone(),
                (Instant::now() + PROTOCOL_COST_MODELS_CACHE, cached.clone()),
            );
            cache.refreshing.remove(&key);
        }
        upstream.cost_models_ready.notify_waiters();

        assert_eq!(waiter.await.expect("joined").expect("cached"), cached);
    }
}
