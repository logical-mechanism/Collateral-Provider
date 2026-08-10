//! HTTP surface.
//!
//! ```text
//! POST /<environment>/collateral/   { "tx": "<hex cbor>" } -> { "witness": "<hex cbor>" }
//! GET  /healthz                                            -> { "status": "ok", "version": "..." }
//! GET  /livez                                              -> { "status": "ok", "version": "..." }
//! GET  /known_hosts/                                       -> registry JSON
//! GET  /metrics                                            -> Prometheus text (off by default)
//! GET  /api/schema                                         -> OpenAPI JSON
//! ```
//!
//! The HTML landing page and the Swagger/ReDoc UIs stay in the Django
//! service — this binary is the API only. Every other path answers
//! `{"detail": "Not Found"}` with a 404 rather than redirecting, because
//! mainstream HTTP clients follow redirects by default and a mistyped
//! collateral URL would otherwise look like a success.

use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::time::Instant;

use axum::extract::rejection::PathRejection;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use futures_util::FutureExt;
use serde_json::{json, Value as JsonValue};

use crate::error::{detail_response, ApiError, ApiResult};
use crate::health::readiness_problems;
use crate::middleware::{body_limit, host, metrics as metrics_middleware, request_id};
use crate::net;
use crate::services::collateral::issue_witness;
use crate::state::AppState;
use crate::throttle::ThrottleDecision;
use crate::VERSION;

/// The Prometheus text exposition format this binary emits.
///
/// Deliberately pinned rather than tracking `prometheus_client`: the Python
/// service's pinned 0.25.0 advertises `version=1.0.0`, but the two formats are
/// wire-identical for the counter and histogram families used here, and every
/// scraper in circulation accepts 0.0.4.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The throttle bucket for a caller whose address could not be established.
/// DRF formats `None` into its cache key, so those callers share one bucket
/// there too — never an unlimited one.
const UNIDENTIFIED: &str = "unidentified";

/// `Allow` for the collateral endpoint, matching DRF's `allowed_methods`.
const COLLATERAL_ALLOW: &str = "POST, OPTIONS";

/// `Allow` for the read-only endpoints. Unlike DRF these also serve `HEAD`,
/// which axum derives from the `GET` handler — see rs/README.md.
const READ_ONLY_ALLOW: &str = "GET, HEAD, OPTIONS";

/// A forwarded hop that could not be read as text. `net::client_ip` fails
/// closed on an unparseable hop, so substituting a token that can never parse
/// reproduces what Django does with a header byte it cannot decode, while
/// keeping the position of the surrounding hops intact.
const UNREADABLE_HOP: &str = "?";

/// Build the full router with middleware applied in the same order as the
/// Django stack: CORS, request id, metrics, body limit, host check.
pub fn app(state: AppState) -> Router {
    // The first `.layer` call is the innermost wrapper, so this list reads
    // inside-out: catch-panic sits closest to the handlers (so the metrics
    // middleware still observes a panic as a 500) and CORS sits outermost.
    Router::new()
        // `any`, not `post`: DRF throttles in `initial()`, which runs before
        // method dispatch, so a wrong method on the collateral path is metered
        // too. Routing POST alone would hand those to the router's 405
        // fallback, leaving the endpoint's only abuse control off for a request
        // `body_limit` has already buffered up to the cap.
        .route("/{environment}/collateral", any(collateral_entry))
        .route("/{environment}/collateral/", any(collateral_entry))
        .route("/healthz", get(healthz))
        .route("/healthz/", get(healthz))
        .route("/livez", get(livez))
        .route("/livez/", get(livez))
        .route("/known_hosts", get(known_hosts))
        .route("/known_hosts/", get(known_hosts))
        // `any`, not `get`: Django's `metrics_view` carries no `@require_GET`,
        // so every method 404s while metrics are off. Routing GET alone would
        // answer 405 for the others and tell a scanner the endpoint exists.
        .route("/metrics", any(metrics))
        .route("/metrics/", any(metrics))
        .route("/api/schema", get(schema))
        .route("/api/schema/", get(schema))
        .method_not_allowed_fallback(method_not_allowed)
        .fallback(not_found)
        .layer(from_fn(catch_panic))
        .layer(from_fn_with_state(state.clone(), body_limit::middleware))
        .layer(from_fn_with_state(
            state.clone(),
            metrics_middleware::middleware,
        ))
        .layer(from_fn_with_state(state.clone(), host::middleware))
        .layer(from_fn(request_id::middleware))
        .layer(from_fn(security_headers))
        // `CORS_ALLOW_ALL_ORIGINS = True`: any page may make its visitors call
        // the endpoint, which is why the throttle keys on the visitor's IP.
        .layer(from_fn(cors))
        .with_state(state)
}

/// The static OpenAPI document served at `/api/schema`.
pub const OPENAPI_JSON: &str = include_str!("openapi.json");

// --- cross-cutting response shaping ------------------------------------------

/// Django's `SecurityMiddleware` and `XFrameOptionsMiddleware` defaults, which
/// the Python service ships and this one was missing entirely.
///
/// `nosniff` is the one that matters for a JSON API: without it a browser may
/// guess a content type for an error body and render it.
async fn security_headers(request: Request, next: Next) -> Response {
    const HEADERS: [(HeaderName, HeaderValue); 4] = [
        (
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ),
        (
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ),
        (
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("same-origin"),
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ),
    ];

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in HEADERS {
        headers.insert(name, value);
    }
    response
}

/// `CORS_ALLOW_ALL_ORIGINS = True`, as django-cors-headers implements it.
///
/// Only a genuine preflight — `OPTIONS` carrying `Access-Control-Request-Method`
/// — is answered here. A bare `OPTIONS` is routed like any other request, so a
/// mistyped path still answers 404 and the collateral endpoint still answers
/// with DRF's metadata document. A blanket CORS layer replies 200 with an empty
/// body to *every* `OPTIONS`, which makes a typo look like a success for the
/// same reason this service does not redirect unknown paths.
async fn cors(request: Request, next: Next) -> Response {
    let origin = request.headers().get(header::ORIGIN).cloned();
    let preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);

    let mut response = if preflight {
        let mut response = StatusCode::OK.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("DELETE, GET, OPTIONS, PATCH, POST, PUT"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(
                "accept, authorization, content-type, user-agent, x-csrftoken, x-requested-with",
            ),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"),
        );
        response
    } else {
        next.run(request).await
    };

    let headers = response.headers_mut();
    // Always varies on origin, even when no origin was sent: the response would
    // have carried `Access-Control-Allow-Origin` had one been, so a cache must
    // not serve this copy to a cross-origin request.
    headers.insert(header::VARY, HeaderValue::from_static("origin"));
    if origin.is_some() {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
    }
    response
}

// --- collateral --------------------------------------------------------------

/// Throttle, then dispatch on method — the order DRF's `initial()` imposes.
async fn collateral_entry(
    State(state): State<AppState>,
    environment: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    // Throttle first, exactly as DRF's `initial()` does before the view body
    // runs. Rejecting an unknown environment first looks cheaper, but it would
    // leave `POST /<anything>/collateral/` unmetered — and `body_limit` has
    // already buffered up to the cap by the time we get here, so no request
    // reaching this handler is free to serve.
    let ip_address = client_ip_of(&request, &state);
    let ident = ip_address
        .clone()
        .unwrap_or_else(|| UNIDENTIFIED.to_string());
    if let ThrottleDecision::Throttled { retry_after } = state.throttle.allow(&ident) {
        return throttled_response(retry_after);
    }

    match *request.method() {
        Method::POST => collateral(state, environment, request, ip_address).await,
        // DRF answers OPTIONS with its metadata document, not an empty body.
        Method::OPTIONS => collateral_metadata(),
        ref method => method_not_allowed_for(method, COLLATERAL_ALLOW),
    }
}

/// `SimpleMetadata`'s document for `ProvideCollateralView`.
fn collateral_metadata() -> Response {
    let mut response = axum::Json(json!({
        "name": "Provide Collateral",
        "description": "",
        "renders": ["application/json"],
        "parses": ["application/json"],
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(COLLATERAL_ALLOW));
    response
}

async fn collateral(
    state: AppState,
    environment: Result<Path<String>, PathRejection>,
    request: Request,
    ip_address: Option<String>,
) -> Response {
    // A path segment that will not percent-decode names no configured
    // network, so it gets the same answer as any other unknown one.
    let Ok(Path(environment)) = environment else {
        return detail_response(StatusCode::BAD_REQUEST, "Invalid Environment");
    };
    // The value is attacker-controlled and reaches the log verbatim in the
    // Python service; quote it here so a decoded control character cannot
    // forge a second log line.
    tracing::debug!(target: "api", "Collateral request received: env={:?}", environment);

    let Some(env_config) = state.config.environment(&environment).cloned() else {
        tracing::warn!(target: "api", "Invalid collateral environment: env={:?}", environment);
        return detail_response(StatusCode::BAD_REQUEST, "Invalid Environment");
    };

    if !is_json_content_type(request.headers()) {
        // DRF names the media type it refused; a bare "Unsupported Media Type"
        // leaves the caller guessing which header was wrong.
        return detail_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &format!(
                "Unsupported media type \"{}\" in request.",
                raw_content_type(request.headers()).unwrap_or_default()
            ),
        );
    }

    let (_parts, body) = request.into_parts();
    // `body_limit` already bounded this path; the cap here only keeps a body
    // that slipped past a missing Content-Length from being buffered whole.
    let bytes = match axum::body::to_bytes(body, state.config.max_body_size.saturating_add(1)).await
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return detail_response(StatusCode::BAD_REQUEST, "Request Body Could Not Be Read")
        }
    };

    let payload: JsonValue = if bytes.is_empty() {
        // DRF's JSONParser yields an empty dict for an empty stream, so the
        // caller hears about the missing field rather than a parse error.
        JsonValue::Object(serde_json::Map::new())
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(payload) => payload,
            // DRF's JSONParser wraps the decoder's own message, which names the
            // offending line and column — the only thing that makes a malformed
            // body debuggable from the response alone.
            Err(err) => {
                return ApiError::validation(format!("JSON parse error - {err}")).into_response()
            }
        }
    };

    let tx = match parse_request(&payload) {
        Ok(tx) => tx,
        Err(err) => return err.into_response(),
    };

    let started = Instant::now();
    match issue_witness(
        &state,
        &tx.tx,
        &environment,
        &env_config,
        ip_address.as_deref(),
    )
    .await
    {
        Ok((witness, _tx_hash)) => {
            // Deliberately omits both the client IP and the transaction hash.
            // Keeping those together creates a durable link between a network
            // identity and an on-chain transaction, contrary to the service's
            // privacy goal. The request ID still correlates this line with
            // errors and timings from the same request.
            //
            // `env` and `duration_ms` are emitted as fields as well as in the
            // message: the JSON formatter promotes fields to top-level keys, so
            // a log pipeline can index them, while the text formatter drops
            // fields and needs them spelled out in the message.
            let duration_ms = started.elapsed().as_millis();
            tracing::info!(
                target: "api",
                env = %environment,
                duration_ms = duration_ms,
                "Witness issued: env={} duration_ms={}",
                environment,
                duration_ms
            );
            (StatusCode::OK, axum::Json(json!({ "witness": witness }))).into_response()
        }
        Err(err) => err.into_response(),
    }
}

/// The validated request body: one required `tx`.
#[cfg_attr(test, derive(Debug))]
struct CollateralRequest {
    tx: String,
}

/// Reproduce `ProvideCollateralSerializer` plus the flattening
/// `util.normalize_error_response` applies to its errors.
///
/// Field order matters: DRF collects every field error into one dict and the
/// handler reports the first by declaration order, so a request that is wrong
/// about both `tx` and `additional_utxos` hears about `tx`.
fn parse_request(payload: &JsonValue) -> ApiResult<CollateralRequest> {
    if payload.is_null() {
        // DRF's `Serializer.run_validation` special-cases a null root before
        // any field validation, so the message names the body, not a field.
        return Err(ApiError::validation("No data provided"));
    }
    let Some(object) = payload.as_object() else {
        return Err(ApiError::validation(format!(
            "Invalid data. Expected a dictionary, but got {}.",
            python_type_name(payload)
        )));
    };

    let tx = validate_tx(object.get("tx"))?;
    validate_additional_utxos(object.get("additional_utxos"))?;
    // Unknown members are ignored, as DRF does.
    Ok(CollateralRequest { tx })
}

fn validate_tx(value: Option<&JsonValue>) -> ApiResult<String> {
    let Some(value) = value else {
        return Err(ApiError::validation("Missing required field: 'tx'"));
    };
    match value {
        JsonValue::Null => Err(ApiError::validation("Field 'tx' may not be null")),
        JsonValue::String(text) => {
            // `trim_whitespace=True` runs before the blank check, so a
            // whitespace-only value is blank rather than a one-space tx.
            let trimmed = text.trim();
            if trimmed.is_empty() {
                Err(ApiError::validation("Field 'tx' may not be blank"))
            } else {
                Ok(trimmed.to_string())
            }
        }
        // CharField is lenient with plain numerics and coerces them with
        // `str()`. Booleans, arrays and objects are likely user error and
        // DRF refuses them outright.
        JsonValue::Number(number) => Ok(number.to_string()),
        _ => Err(ApiError::validation("tx: Not a valid string.")),
    }
}

fn validate_additional_utxos(value: Option<&JsonValue>) -> ApiResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    match value {
        JsonValue::Null => Err(ApiError::validation(
            "Field 'additional_utxos' may not be null",
        )),
        JsonValue::Array(items) if items.is_empty() => Ok(()),
        // An unseen parent reference does not authenticate its future output,
        // so a non-empty value can never be forwarded to the evaluator.
        JsonValue::Array(_) => Err(ApiError::validation(
            "additional_utxos: additional_utxos is not supported; \
             submit only ledger-resolved inputs.",
        )),
        other => Err(ApiError::validation(format!(
            "additional_utxos: Expected a list of items but got type \"{}\".",
            python_type_name(other)
        ))),
    }
}

/// `type(value).__name__` for the JSON types DRF can see.
fn python_type_name(value: &JsonValue) -> &'static str {
    match value {
        JsonValue::Null => "NoneType",
        JsonValue::Bool(_) => "bool",
        JsonValue::Number(number) => {
            if number.is_f64() {
                "float"
            } else {
                "int"
            }
        }
        JsonValue::String(_) => "str",
        JsonValue::Array(_) => "list",
        JsonValue::Object(_) => "dict",
    }
}

/// DRF's `Throttled`, including its singular/plural wording and the
/// `Retry-After` header its exception handler attaches.
fn throttled_response(retry_after: u64) -> Response {
    let unit = if retry_after == 1 {
        "second"
    } else {
        "seconds"
    };
    let mut response = detail_response(
        StatusCode::TOO_MANY_REQUESTS,
        &format!("Request was throttled. Expected available in {retry_after} {unit}."),
    );
    if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// The raw `Content-Type` header, as DRF's `request.content_type` sees it.
fn raw_content_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
}

/// Parser negotiation, not renderer negotiation: a form-encoded or multipart
/// body gets the documented 415 rather than being silently accepted.
///
/// DRF selects a parser whose media type *matches* the request's, and wildcards
/// match on either side. So `application/json`, `application/*` and `*/*` all
/// reach `JSONParser`, and a request with no `Content-Type` at all falls
/// through to the default parser rather than being refused.
fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(raw) = raw_content_type(headers) else {
        return true;
    };
    let media_type = raw.split(';').next().unwrap_or(raw).trim();
    if media_type.is_empty() {
        return true;
    }
    let Some((main, sub)) = media_type.split_once('/') else {
        return false;
    };
    (main == "*" || main.eq_ignore_ascii_case("application"))
        && (sub == "*" || sub.eq_ignore_ascii_case("json"))
}

/// One place decides who the caller is, so bans, metrics authorization, and
/// throttling always agree.
fn client_ip_of(request: &Request, state: &AppState) -> Option<String> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip());
    let forwarded = forwarded_chain(request.headers());
    net::client_ip(peer, forwarded.as_deref(), &state.config.trusted_proxy_ips)
}

/// Join every `X-Forwarded-For` line into one chain, as WSGI does.
///
/// gunicorn merges duplicate request headers with a comma before Django ever
/// sees them, so `_client_ip` walks the whole chain. `HeaderMap::get` returns
/// only the *first* line, which would let a caller split a spoofed prefix into
/// its own header and win the right-to-left walk — choosing the identity used
/// for throttling, ban matching and the `/metrics` allowlist.
fn forwarded_chain(headers: &HeaderMap) -> Option<String> {
    let mut chain = String::new();
    for value in headers.get_all("x-forwarded-for") {
        if !chain.is_empty() {
            chain.push(',');
        }
        chain.push_str(value.to_str().unwrap_or(UNREADABLE_HOP));
    }
    (!chain.is_empty()).then_some(chain)
}

// --- operational endpoints ---------------------------------------------------

async fn healthz(State(state): State<AppState>) -> Response {
    let problems = readiness_problems(&state.config, &state.keys, &state.throttle);
    let response = if problems.is_empty() {
        (
            StatusCode::OK,
            axum::Json(json!({ "status": "ok", "version": VERSION })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({ "status": "error", "problems": problems })),
        )
            .into_response()
    };
    // Don't let a proxy cache "ok" past the moment the keys disappear.
    no_store(response)
}

async fn livez() -> Response {
    no_store(axum::Json(json!({ "status": "ok", "version": VERSION })).into_response())
}

async fn known_hosts(State(state): State<AppState>) -> Response {
    let registry = state.known_hosts.get();
    // `no-store` because the file hot-reloads; a proxy serving a stale
    // registry would defeat that.
    no_store(axum::Json(registry.as_ref()).into_response())
}

async fn metrics(State(state): State<AppState>, request: Request) -> Response {
    // Off by default, and indistinguishable from an unrouted path when off:
    // a casual scraper gets no hint the service exposes metrics at all.
    if !state.config.metrics_enabled {
        return detail_response(StatusCode::NOT_FOUND, "Not Found");
    }
    let authorized = client_ip_of(&request, &state)
        .as_deref()
        .and_then(net::parse_ip)
        .is_some_and(|ip| state.config.metrics_allow_ips.contains(&ip));
    if !authorized {
        // No raw IP in the line: an observability rejection is not a reason to
        // start persisting caller addresses.
        tracing::warn!(target: "api", "Rejected unauthorized /metrics request");
        return detail_response(StatusCode::FORBIDDEN, "Forbidden");
    }
    (
        [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        state.metrics.gather(),
    )
        .into_response()
}

async fn schema() -> Response {
    ([(header::CONTENT_TYPE, "application/json")], OPENAPI_JSON).into_response()
}

async fn not_found() -> Response {
    detail_response(StatusCode::NOT_FOUND, "Not Found")
}

/// Only the read-only routes reach this: the collateral endpoint routes `any`
/// so it can throttle first, and `/metrics` routes `any` so it can 404.
async fn method_not_allowed(request: Request) -> Response {
    method_not_allowed_for(request.method(), READ_ONLY_ALLOW)
}

/// DRF's `MethodNotAllowed`, including the quoted verb and the `Allow` header
/// its exception handler attaches.
fn method_not_allowed_for(method: &Method, allow: &'static str) -> Response {
    let mut response = detail_response(
        StatusCode::METHOD_NOT_ALLOWED,
        &format!("Method \"{method}\" not allowed."),
    );
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allow));
    response
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// --- panics ------------------------------------------------------------------

/// Keep the `{"detail": ...}` envelope for errors that escape a handler.
///
/// Sits inside the request-id scope so the ERROR line correlates with the rest
/// of the request, and inside the metrics middleware so a panic is still
/// counted as the 500 the caller received.
async fn catch_panic(request: Request, next: Next) -> Response {
    // The raw URI path is never percent-decoded, so it cannot smuggle a
    // newline into the log line.
    let path = request.uri().path().to_string();
    match AssertUnwindSafe(next.run(request)).catch_unwind().await {
        Ok(response) => response,
        Err(panic) => {
            tracing::error!(
                target: "api",
                "Unhandled server error at {}: {}",
                path,
                panic_message(panic.as_ref())
            );
            detail_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        }
    }
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_string()
    } else {
        "unknown panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use tower::ServiceExt;

    const PKH: &str = "6af53ff4f054348ad825c692dd9db8f1760a8e0eacf9af9f99306513";

    fn test_config() -> Config {
        let env: HashMap<&str, String> = [
            ("PKH", PKH.to_string()),
            ("ENVIRONMENT", "development".to_string()),
            ("PREPROD_NETWORK", "--testnet-magic 1".to_string()),
            ("PREPROD_TXID", "a1".repeat(32)),
            ("PREPROD_TXIDX", "0".to_string()),
            ("MAINNET_NETWORK", "--mainnet".to_string()),
            ("MAINNET_TXID", "b2".repeat(32)),
            ("MAINNET_TXIDX", "1".to_string()),
        ]
        .into_iter()
        .collect();
        Config::from_lookup(&|key| env.get(key).cloned()).expect("test config builds")
    }

    fn router_with(config: Config) -> Router {
        app(AppState::new(config).expect("state builds"))
    }

    fn router() -> Router {
        router_with(test_config())
    }

    /// Every request needs a Host the development allowlist accepts.
    fn get_request(uri: &str) -> Request {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::HOST, "127.0.0.1")
            .body(Body::empty())
            .expect("request builds")
    }

    /// `body_limit` answers 411 without a Content-Length, so post it.
    fn post_json(uri: &str, body: &str) -> Request {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, body.len())
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    async fn body_json(response: Response) -> JsonValue {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("body is JSON")
    }

    async fn send(router: Router, request: Request) -> Response {
        router.oneshot(request).await.expect("router responds")
    }

    /// The detail string of a POST to `/preprod/collateral`.
    async fn collateral_detail(body: &str) -> (StatusCode, String) {
        let response = send(router(), post_json("/preprod/collateral", body)).await;
        let status = response.status();
        let detail = body_json(response).await["detail"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        (status, detail)
    }

    // --- shape validation ---------------------------------------------------

    #[test]
    fn tx_shape_errors_match_the_drf_wording() {
        let cases = [
            (json!({}), "Missing required field: 'tx'"),
            (json!({"tx": null}), "Field 'tx' may not be null"),
            (json!({"tx": ""}), "Field 'tx' may not be blank"),
            (json!({"tx": "   "}), "Field 'tx' may not be blank"),
            (json!({"tx": true}), "tx: Not a valid string."),
            (json!({"tx": []}), "tx: Not a valid string."),
            (json!({"tx": {}}), "tx: Not a valid string."),
        ];
        for (payload, expected) in cases {
            let err = parse_request(&payload).expect_err("rejected");
            assert_eq!(err.detail(), expected, "{payload}");
            assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn tx_is_trimmed_and_numbers_are_coerced() {
        assert_eq!(
            parse_request(&json!({"tx": "  deadbeef  "}))
                .expect("valid")
                .tx,
            "deadbeef"
        );
        // CharField is lenient with plain numerics: `str(12)` and `str(1.5)`.
        assert_eq!(parse_request(&json!({"tx": 12})).expect("valid").tx, "12");
        assert_eq!(parse_request(&json!({"tx": 1.5})).expect("valid").tx, "1.5");
    }

    #[test]
    fn additional_utxos_is_a_compatibility_field_only() {
        assert!(parse_request(&json!({"tx": "de"})).is_ok());
        assert!(parse_request(&json!({"tx": "de", "additional_utxos": []})).is_ok());
        // Unknown members are ignored, as DRF does.
        assert!(parse_request(&json!({"tx": "de", "nope": 1})).is_ok());

        let err = parse_request(&json!({"tx": "de", "additional_utxos": [{"a": 1}]}))
            .expect_err("rejected");
        assert_eq!(
            err.detail(),
            "additional_utxos: additional_utxos is not supported; \
             submit only ledger-resolved inputs."
        );

        let err =
            parse_request(&json!({"tx": "de", "additional_utxos": null})).expect_err("rejected");
        assert_eq!(err.detail(), "Field 'additional_utxos' may not be null");

        for (value, name) in [
            (json!("x"), "str"),
            (json!(1), "int"),
            (json!(1.5), "float"),
            (json!(true), "bool"),
            (json!({}), "dict"),
        ] {
            let err = parse_request(&json!({"tx": "de", "additional_utxos": value}))
                .expect_err("rejected");
            assert_eq!(
                err.detail(),
                format!("additional_utxos: Expected a list of items but got type \"{name}\".")
            );
        }
    }

    #[test]
    fn tx_errors_win_over_additional_utxos_errors() {
        // DRF reports the first field in declaration order, and `tx` is first.
        let err = parse_request(&json!({"additional_utxos": "x"})).expect_err("rejected");
        assert_eq!(err.detail(), "Missing required field: 'tx'");
    }

    #[test]
    fn a_non_object_body_is_rejected_like_a_serializer_would() {
        assert_eq!(
            parse_request(&json!([])).expect_err("rejected").detail(),
            "Invalid data. Expected a dictionary, but got list."
        );
        assert_eq!(
            parse_request(&json!("tx")).expect_err("rejected").detail(),
            "Invalid data. Expected a dictionary, but got str."
        );
        assert_eq!(
            parse_request(&JsonValue::Null)
                .expect_err("rejected")
                .detail(),
            "No data provided"
        );
    }

    #[test]
    fn content_type_accepts_parameters_but_not_other_media_types() {
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
            is_json_content_type(&headers)
        };
        assert!(with("application/json"));
        assert!(with("application/json; charset=utf-8"));
        assert!(with("Application/JSON"));
        // DRF matches parsers on wildcards from either side, and falls through
        // to the default parser when the header is absent or empty.
        assert!(with("application/*"));
        assert!(with("*/*"));
        assert!(with(""));
        assert!(is_json_content_type(&HeaderMap::new()));
        assert!(!with("text/plain"));
        assert!(!with("text/json"));
        assert!(!with("application/xml"));
        assert!(!with("application/x-www-form-urlencoded"));
        assert!(!with("json"));
    }

    #[test]
    fn throttled_wording_and_header_match_drf() {
        let response = throttled_response(42);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("42")
        );
    }

    #[tokio::test]
    async fn throttled_body_is_the_detail_envelope() {
        let body = body_json(throttled_response(42)).await;
        assert_eq!(
            body["detail"],
            json!("Request was throttled. Expected available in 42 seconds.")
        );
        // DRF's ngettext picks the singular for exactly one second.
        let body = body_json(throttled_response(1)).await;
        assert_eq!(
            body["detail"],
            json!("Request was throttled. Expected available in 1 second.")
        );
    }

    // --- routing ------------------------------------------------------------

    #[tokio::test]
    async fn unknown_paths_are_a_json_404() {
        for uri in ["/", "/no/such/endpoint", "/preprod/collaterall/"] {
            let response = send(router(), get_request(uri)).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(body_json(response).await, json!({"detail": "Not Found"}));
        }
    }

    #[tokio::test]
    async fn a_wrong_method_on_a_known_path_is_405() {
        let response = send(router(), get_request("/preprod/collateral")).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        // DRF quotes the verb and advertises OPTIONS alongside POST.
        assert_eq!(
            response
                .headers()
                .get(header::ALLOW)
                .and_then(|value| value.to_str().ok()),
            Some("POST, OPTIONS")
        );
        assert_eq!(
            body_json(response).await,
            json!({"detail": "Method \"GET\" not allowed."})
        );

        let response = send(router(), get_request("/known_hosts/")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let request = Request::builder()
            .method("DELETE")
            .uri("/known_hosts/")
            .header(header::HOST, "127.0.0.1")
            .body(Body::empty())
            .expect("request builds");
        let response = send(router(), request).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "Method \"DELETE\" not allowed."})
        );
    }

    #[test]
    fn every_forwarded_header_line_joins_into_one_chain() {
        // gunicorn merges duplicate headers with a comma before Django sees
        // them. Reading only the first line would let a caller split a spoofed
        // prefix into its own header and win the right-to-left walk.
        let mut headers = HeaderMap::new();
        assert_eq!(forwarded_chain(&headers), None);

        headers.append("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        assert_eq!(forwarded_chain(&headers).as_deref(), Some("9.9.9.9"));

        headers.append("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        assert_eq!(
            forwarded_chain(&headers).as_deref(),
            Some("9.9.9.9,1.2.3.4")
        );
    }

    #[test]
    fn a_split_forwarded_header_cannot_pick_the_client_identity() {
        use crate::net;
        let trusted = net::parse_networks(&["127.0.0.1".to_string()]);
        let peer = Some("127.0.0.1".parse().expect("valid ip"));

        let mut split = HeaderMap::new();
        split.append("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        split.append("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        let mut merged = HeaderMap::new();
        merged.insert(
            "x-forwarded-for",
            HeaderValue::from_static("9.9.9.9,1.2.3.4"),
        );

        // The two are the same bytes on the wire, so they must resolve alike —
        // to the hop the trusted proxy appended, not the caller's prefix.
        let of = |headers: &HeaderMap| {
            net::client_ip(peer, forwarded_chain(headers).as_deref(), &trusted)
        };
        assert_eq!(of(&split).as_deref(), Some("1.2.3.4"));
        assert_eq!(of(&split), of(&merged));
    }

    #[test]
    fn an_unreadable_forwarded_hop_keeps_the_positions_of_the_rest() {
        let mut headers = HeaderMap::new();
        headers.append(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"\xff").expect("opaque header value"),
        );
        headers.append("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        // The unreadable line becomes a hop that cannot parse rather than
        // vanishing, so the rightmost hop is still read first.
        assert_eq!(forwarded_chain(&headers).as_deref(), Some("?,1.2.3.4"));
    }

    #[tokio::test]
    async fn every_response_carries_djangos_security_headers() {
        let response = send(router(), get_request("/livez")).await;
        let headers = response.headers().clone();
        for (name, value) in [
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "same-origin"),
            ("cross-origin-opener-policy", "same-origin"),
        ] {
            assert_eq!(
                headers.get(name).and_then(|v| v.to_str().ok()),
                Some(value),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn only_a_real_preflight_short_circuits_options() {
        // With Access-Control-Request-Method this is a preflight and answers
        // 200 with the CORS headers a browser needs.
        let preflight = Request::builder()
            .method("OPTIONS")
            .uri("/nope")
            .header(header::HOST, "127.0.0.1")
            .header(header::ORIGIN, "https://example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(Body::empty())
            .expect("request builds");
        let response = send(router(), preflight).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_MAX_AGE)
                .and_then(|v| v.to_str().ok()),
            Some("86400")
        );

        // Without it, the request routes normally — so a mistyped path is a
        // 404 rather than an empty 200 that reads as success.
        let bare = Request::builder()
            .method("OPTIONS")
            .uri("/nope")
            .header(header::HOST, "127.0.0.1")
            .body(Body::empty())
            .expect("request builds");
        let response = send(router(), bare).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(response).await, json!({"detail": "Not Found"}));
    }

    #[tokio::test]
    async fn options_on_the_collateral_path_returns_drf_metadata() {
        let request = Request::builder()
            .method("OPTIONS")
            .uri("/preprod/collateral/")
            .header(header::HOST, "127.0.0.1")
            .body(Body::empty())
            .expect("request builds");
        let response = send(router(), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::ALLOW)
                .and_then(|v| v.to_str().ok()),
            Some("POST, OPTIONS")
        );
        assert_eq!(
            body_json(response).await,
            json!({
                "name": "Provide Collateral",
                "description": "",
                "renders": ["application/json"],
                "parses": ["application/json"],
            })
        );
    }

    #[tokio::test]
    async fn an_empty_body_names_the_missing_field() {
        // DRF's JSONParser yields an empty dict for an empty stream, so the
        // caller hears about `tx` rather than a parse error.
        let (status, detail) = collateral_detail("").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(detail, "Missing required field: 'tx'");
    }

    #[tokio::test]
    async fn a_wildcard_content_type_is_parsed_as_json() {
        for content_type in ["application/*", "*/*"] {
            let body = r#"{"tx":"zz"}"#;
            let request = Request::builder()
                .method("POST")
                .uri("/preprod/collateral")
                .header(header::HOST, "127.0.0.1")
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, body.len())
                .body(Body::from(body))
                .expect("request builds");
            let response = send(router(), request).await;
            // Parsed, then refused by a validator — not refused as a media type.
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{content_type}");
            assert_eq!(
                body_json(response).await,
                json!({"detail": "Invalid Hex Data In Tx"}),
                "{content_type}"
            );
        }
    }

    #[tokio::test]
    async fn a_wrong_method_still_spends_throttle_budget() {
        let mut config = test_config();
        config.throttle_rate = "1/min".parse().expect("valid rate");
        let router = router_with(config);

        let first = send(router.clone(), get_request("/preprod/collateral/")).await;
        assert_eq!(first.status(), StatusCode::METHOD_NOT_ALLOWED);
        // DRF meters in `initial()`, before method dispatch, so the 405 counts.
        let second = send(router, get_request("/preprod/collateral/")).await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn healthz_reports_the_missing_signing_identity() {
        let response = send(router(), get_request("/healthz")).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let body = body_json(response).await;
        assert_eq!(body["status"], json!("error"));
        assert_eq!(body["problems"], json!(["skey missing"]));
    }

    #[tokio::test]
    async fn livez_is_always_ok() {
        for uri in ["/livez", "/livez/"] {
            let response = send(router(), get_request(uri)).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("no-store")
            );
            assert_eq!(
                body_json(response).await,
                json!({"status": "ok", "version": VERSION})
            );
        }
    }

    #[tokio::test]
    async fn known_hosts_serves_an_object_with_no_store() {
        let response = send(router(), get_request("/known_hosts/")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert!(body_json(response).await.is_object());
    }

    #[tokio::test]
    async fn metrics_is_indistinguishable_from_an_unrouted_path_when_disabled() {
        let response = send(router(), get_request("/metrics")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(response).await, json!({"detail": "Not Found"}));
    }

    /// Django's `metrics_view` carries no `@require_GET`, so with metrics off
    /// every method answers 404. Routing GET alone would answer 405 for the
    /// others, which is exactly the hint the endpoint is meant not to give.
    #[tokio::test]
    async fn metrics_is_indistinguishable_from_an_unrouted_path_for_every_method() {
        for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD"] {
            let request = Request::builder()
                .method(method)
                .uri("/metrics")
                .header(header::HOST, "127.0.0.1")
                .header(header::CONTENT_LENGTH, "0")
                .body(Body::empty())
                .expect("request builds");
            let response = send(router(), request).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method}");
            // An unrouted path answers the same way, byte for byte.
            let unrouted = Request::builder()
                .method(method)
                .uri("/definitely-not-a-route")
                .header(header::HOST, "127.0.0.1")
                .header(header::CONTENT_LENGTH, "0")
                .body(Body::empty())
                .expect("request builds");
            let other = send(router(), unrouted).await;
            assert_eq!(other.status(), StatusCode::NOT_FOUND, "{method}");
        }
    }

    #[tokio::test]
    async fn metrics_rejects_an_unknown_client() {
        let mut config = test_config();
        config.metrics_enabled = true;
        // No ConnectInfo in a oneshot request, so the caller has no identity.
        let response = send(router_with(config), get_request("/metrics")).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn the_schema_endpoint_serves_parseable_openapi() {
        let response = send(router(), get_request("/api/schema")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let document = body_json(response).await;
        assert_eq!(document["openapi"], json!("3.0.3"));
        assert!(document["paths"]["/{environment}/collateral/"].is_object());
    }

    #[tokio::test]
    async fn cors_allows_any_origin() {
        let request = Request::builder()
            .method("GET")
            .uri("/livez")
            .header(header::HOST, "127.0.0.1")
            .header(header::ORIGIN, "https://wallet.example")
            .body(Body::empty())
            .expect("request builds");
        let response = send(router(), request).await;
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
    }

    // --- collateral endpoint -------------------------------------------------

    #[tokio::test]
    async fn an_unknown_environment_is_rejected_before_the_body_is_read() {
        // No Content-Type and no body: the environment check must still win,
        // otherwise the caller hears 415 about a request that was never valid.
        let request = Request::builder()
            .method("POST")
            .uri("/fakenet/collateral/")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .expect("request builds");
        let response = send(router(), request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "Invalid Environment"})
        );
    }

    #[tokio::test]
    async fn a_non_json_content_type_is_415() {
        let request = Request::builder()
            .method("POST")
            .uri("/preprod/collateral")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_LENGTH, "2")
            .body(Body::from("{}"))
            .expect("request builds");
        let response = send(router(), request).await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        // DRF names the media type it refused.
        assert_eq!(
            body_json(response).await,
            json!({"detail": "Unsupported media type \"text/plain\" in request."})
        );
    }

    #[tokio::test]
    async fn malformed_json_names_the_parse_error() {
        let (status, detail) = collateral_detail("{not json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(detail.starts_with("JSON parse error - "), "{detail}");
    }

    #[tokio::test]
    async fn shape_errors_surface_through_the_endpoint() {
        assert_eq!(
            collateral_detail("{}").await,
            (
                StatusCode::BAD_REQUEST,
                "Missing required field: 'tx'".into()
            )
        );
        assert_eq!(
            collateral_detail(r#"{"tx": ""}"#).await,
            (
                StatusCode::BAD_REQUEST,
                "Field 'tx' may not be blank".into()
            )
        );
    }

    #[tokio::test]
    async fn a_pipeline_failure_uses_the_detail_envelope() {
        let (status, detail) = collateral_detail(r#"{"tx": "not-hex"}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(detail, "Invalid Hex Data In Tx");
    }

    #[tokio::test]
    async fn a_missing_content_length_is_411() {
        let request = Request::builder()
            .method("POST")
            .uri("/preprod/collateral")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"tx":"de"}"#))
            .expect("request builds");
        let response = send(router(), request).await;
        assert_eq!(response.status(), StatusCode::LENGTH_REQUIRED);
    }

    #[tokio::test]
    async fn the_host_allowlist_is_enforced() {
        let request = Request::builder()
            .method("GET")
            .uri("/livez")
            .header(header::HOST, "evil.example")
            .body(Body::empty())
            .expect("request builds");
        let response = send(router(), request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "Invalid Host Header"})
        );
    }

    #[tokio::test]
    async fn every_response_carries_a_request_id() {
        let request = Request::builder()
            .method("GET")
            .uri("/livez")
            .header(header::HOST, "127.0.0.1")
            .header("x-request-id", "wallet-request-42")
            .body(Body::empty())
            .expect("request builds");
        let response = send(router(), request).await;
        assert_eq!(
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("wallet-request-42")
        );
    }

    #[tokio::test]
    async fn the_throttle_eventually_answers_429() {
        let mut config = test_config();
        config.throttle_rate = "2/min".parse().expect("valid rate");
        let router = router_with(config);

        for _ in 0..2 {
            let response = send(
                router.clone(),
                post_json("/preprod/collateral", r#"{"tx":"not-hex"}"#),
            )
            .await;
            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        let response = send(
            router.clone(),
            post_json("/preprod/collateral", r#"{"tx":"not-hex"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));
    }

    /// DRF throttles in `initial()`, before the view body reaches its
    /// environment check, so `POST /<anything>/collateral/` is metered too.
    /// It has to be: `body_limit` buffers up to the cap for any path matching
    /// the collateral route, so an unknown environment is not a free request,
    /// and a made-up path segment is the most trivially generated flood there
    /// is.
    #[tokio::test]
    async fn an_unknown_environment_still_spends_throttle_budget() {
        let mut config = test_config();
        config.throttle_rate = "1/min".parse().expect("valid rate");
        let router = router_with(config);

        let first = send(
            router.clone(),
            post_json("/fakenet/collateral/", r#"{"tx":"de"}"#),
        )
        .await;
        assert_eq!(first.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(first).await,
            json!({"detail": "Invalid Environment"})
        );

        // The budget is one per minute and the first request spent it, whether
        // or not the environment existed.
        let second = send(
            router.clone(),
            post_json("/fakenet/collateral/", r#"{"tx":"de"}"#),
        )
        .await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        // The same bucket, so a real environment is throttled by it too.
        let third = send(
            router.clone(),
            post_json("/preprod/collateral/", r#"{"tx":"de"}"#),
        )
        .await;
        assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_panicking_handler_becomes_a_json_500() {
        async fn boom() -> Response {
            panic!("boom");
        }
        let router = Router::new()
            .route("/boom", get(boom))
            .layer(from_fn(catch_panic));
        let response = send(router, get_request("/boom")).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "Internal Server Error"})
        );
    }
}
