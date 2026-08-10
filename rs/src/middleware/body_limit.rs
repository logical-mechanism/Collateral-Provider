//! Enforce the collateral request cap before the body is parsed.
//!
//! A request with no `Content-Length` is answered with 411 rather than being
//! processed: naming the real problem is worth more to an integrator than a
//! misleading 400 about a missing `tx` field. A length over the cap, or a body
//! that turns out to exceed it while streaming, is answered with 413.
//!
//! Only `POST /<env>/collateral/` is affected.

use axum::extract::Request;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use crate::error::detail_response;
use crate::middleware::collateral_path_re;
use crate::state::AppState;

const LENGTH_REQUIRED: &str = "Content-Length Header Is Required";
const INVALID_LENGTH: &str = "Invalid Content-Length";
const TOO_LARGE: &str = "Request Body Too Large";

pub async fn middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    enforce(state.config.max_body_size, request, next).await
}

/// The limit is a parameter so the check is exercisable without the whole
/// application state.
pub(crate) async fn enforce(limit: usize, request: Request, next: Next) -> Response {
    if request.method() != Method::POST || !collateral_path_re().is_match(request.uri().path()) {
        return next.run(request).await;
    }

    if let Some((status, detail)) = declared_length_problem(request.headers(), limit) {
        return detail_response(status, detail);
    }

    // The header is a claim, not a fact. Read at most `limit + 1` bytes so a
    // body that lies about its length is still refused rather than buffered
    // whole, then hand the bounded bytes to the parser.
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, limit.saturating_add(1)).await {
        Ok(bytes) => bytes,
        // `to_bytes` collapses "over the bound" and "the peer went away" into
        // one error; the caller of an oversize body is the one still listening.
        Err(_) => return detail_response(StatusCode::PAYLOAD_TOO_LARGE, TOO_LARGE),
    };
    if bytes.len() > limit {
        return detail_response(StatusCode::PAYLOAD_TOO_LARGE, TOO_LARGE);
    }

    next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
        .await
}

/// Judge the declared `Content-Length` alone, before a byte is read.
fn declared_length_problem(
    headers: &HeaderMap,
    limit: usize,
) -> Option<(StatusCode, &'static str)> {
    let Some(raw) = headers.get(header::CONTENT_LENGTH) else {
        return Some((StatusCode::LENGTH_REQUIRED, LENGTH_REQUIRED));
    };
    let Ok(raw) = raw.to_str() else {
        return Some((StatusCode::BAD_REQUEST, INVALID_LENGTH));
    };
    // Python's `if not raw_length` is falsy only for the empty string; a
    // whitespace-only value reaches `int()` and fails there instead.
    if raw.is_empty() {
        return Some((StatusCode::LENGTH_REQUIRED, LENGTH_REQUIRED));
    }
    // i128 rather than usize: `int("999999999999999999999")` succeeds in
    // Python and answers 413, so an absurd length must not become a 400.
    let Ok(declared) = raw.trim().parse::<i128>() else {
        return Some((StatusCode::BAD_REQUEST, INVALID_LENGTH));
    };
    if declared < 0 {
        return Some((StatusCode::BAD_REQUEST, INVALID_LENGTH));
    }
    if declared > limit as i128 {
        return Some((StatusCode::PAYLOAD_TOO_LARGE, TOO_LARGE));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::post;
    use axum::Router;
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tower::ServiceExt;

    const LIMIT: usize = 128;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            let name: header::HeaderName = name.parse().expect("valid header name");
            headers.insert(name, value.parse().expect("valid header value"));
        }
        headers
    }

    /// A router whose handler flips a flag, so a test can prove the view never
    /// ran — the Python tests' `mock_view.assert_not_called()`.
    fn app(reached: Arc<AtomicBool>) -> Router {
        Router::new()
            .route(
                "/{environment}/collateral/",
                post(move |body: axum::body::Bytes| {
                    let reached = Arc::clone(&reached);
                    async move {
                        reached.store(true, Ordering::SeqCst);
                        format!("{}", body.len())
                    }
                }),
            )
            .layer(axum::middleware::from_fn(|request, next| {
                enforce(LIMIT, request, next)
            }))
    }

    struct Outcome {
        status: StatusCode,
        detail: Option<String>,
        reached_view: bool,
    }

    async fn post_body(path: &str, body: Vec<u8>, content_length: Option<&str>) -> Outcome {
        let reached = Arc::new(AtomicBool::new(false));
        let mut builder = Request::builder().method(Method::POST).uri(path);
        if let Some(value) = content_length {
            builder = builder.header(header::CONTENT_LENGTH, value);
        }
        let request = builder.body(Body::from(body)).expect("request builds");
        let response = app(Arc::clone(&reached))
            .oneshot(request)
            .await
            .expect("service responds");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        let detail = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| value["detail"].as_str().map(str::to_string));
        Outcome {
            status,
            detail,
            reached_view: reached.load(Ordering::SeqCst),
        }
    }

    #[tokio::test]
    async fn a_body_within_the_cap_reaches_the_view() {
        let outcome = post_body("/preprod/collateral/", vec![b'x'; 10], Some("10")).await;
        assert_eq!(outcome.status, StatusCode::OK);
        assert!(outcome.reached_view);
    }

    #[tokio::test]
    async fn a_missing_content_length_is_411_and_the_view_never_runs() {
        let outcome = post_body("/preprod/collateral/", vec![b'x'; 10], None).await;
        assert_eq!(outcome.status, StatusCode::LENGTH_REQUIRED);
        assert_eq!(outcome.detail.as_deref(), Some(LENGTH_REQUIRED));
        assert!(!outcome.reached_view);
    }

    #[tokio::test]
    async fn an_oversize_declared_length_is_413_before_the_body_is_read() {
        let outcome = post_body("/preprod/collateral/", Vec::new(), Some("200000")).await;
        assert_eq!(outcome.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(outcome.detail.as_deref(), Some(TOO_LARGE));
        assert!(!outcome.reached_view);
    }

    #[tokio::test]
    async fn a_body_larger_than_a_truthful_header_claims_is_still_413() {
        // The header is within the cap; the actual bytes are not.
        let outcome = post_body(
            "/preprod/collateral/",
            vec![b'x'; LIMIT + 50],
            Some(&LIMIT.to_string()),
        )
        .await;
        assert_eq!(outcome.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(outcome.detail.as_deref(), Some(TOO_LARGE));
        assert!(!outcome.reached_view);
    }

    #[tokio::test]
    async fn other_paths_and_methods_are_untouched() {
        // GET on the collateral path: no Content-Length, and no 411.
        let reached = Arc::new(AtomicBool::new(false));
        let router = Router::new()
            .route(
                "/{environment}/collateral/",
                axum::routing::get(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn(|request, next| {
                enforce(LIMIT, request, next)
            }));
        let request = Request::builder()
            .uri("/preprod/collateral/")
            .body(Body::empty())
            .expect("request builds");
        assert_eq!(
            router.oneshot(request).await.expect("responds").status(),
            StatusCode::OK
        );
        assert!(!reached.load(Ordering::SeqCst));

        // POST somewhere else: also exempt, even without a Content-Length.
        let outcome = post_body("/known_hosts/", vec![b'x'; 10], None).await;
        assert_eq!(outcome.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn the_path_pattern_matches_with_and_without_a_trailing_slash() {
        assert!(collateral_path_re().is_match("/preprod/collateral/"));
        assert!(collateral_path_re().is_match("/preprod/collateral"));
        assert!(!collateral_path_re().is_match("/preprod/collateral/extra"));
        assert!(!collateral_path_re().is_match("/collateral/"));
    }

    #[test]
    fn declared_length_verdicts() {
        assert_eq!(
            declared_length_problem(&headers(&[]), LIMIT),
            Some((StatusCode::LENGTH_REQUIRED, LENGTH_REQUIRED))
        );
        assert_eq!(
            declared_length_problem(&headers(&[("content-length", "")]), LIMIT),
            Some((StatusCode::LENGTH_REQUIRED, LENGTH_REQUIRED))
        );
        for bad in ["abc", " ", "1.5", "0x10", "-"] {
            assert_eq!(
                declared_length_problem(&headers(&[("content-length", bad)]), LIMIT),
                Some((StatusCode::BAD_REQUEST, INVALID_LENGTH)),
                "{bad:?}"
            );
        }
        assert_eq!(
            declared_length_problem(&headers(&[("content-length", "-1")]), LIMIT),
            Some((StatusCode::BAD_REQUEST, INVALID_LENGTH))
        );
        // Arbitrary-precision in Python, so it must not degrade into a 400.
        assert_eq!(
            declared_length_problem(
                &headers(&[("content-length", "999999999999999999999999")]),
                LIMIT
            ),
            Some((StatusCode::PAYLOAD_TOO_LARGE, TOO_LARGE))
        );
        assert_eq!(
            declared_length_problem(&headers(&[("content-length", "0")]), LIMIT),
            None
        );
        // Exactly at the cap is allowed; one over is not.
        assert_eq!(
            declared_length_problem(&headers(&[("content-length", "128")]), LIMIT),
            None
        );
        assert_eq!(
            declared_length_problem(&headers(&[("content-length", "129")]), LIMIT),
            Some((StatusCode::PAYLOAD_TOO_LARGE, TOO_LARGE))
        );
    }
}
