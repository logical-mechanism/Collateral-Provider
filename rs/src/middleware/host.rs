//! `ALLOWED_HOSTS` enforcement, the equivalent of Django's built-in check.
//!
//! A rejected host answers in the same `{"detail": ...}` envelope as every
//! other error so a misconfigured proxy doesn't hand the integrator an
//! unparseable body.

use std::sync::OnceLock;

use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use regex::Regex;

use crate::error::detail_response;
use crate::state::AppState;

const INVALID_HOST: &str = "Invalid Host Header";

/// Django's `host_validation_re`. A host that fails it has no domain at all,
/// so it matches nothing except the `*` wildcard — an unbracketed IPv6
/// literal or an underscore in the name is rejected rather than guessed at.
fn host_validation_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^([a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9.:]+\])(?::([0-9]+))?$").expect("valid regex")
    })
}

pub async fn middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    enforce(&state.config.allowed_hosts, request, next).await
}

/// The allowlist is a parameter so the check is exercisable without the whole
/// application state.
pub(crate) async fn enforce(allowed: &[String], request: Request, next: Next) -> Response {
    // Only reachable in development: config refuses to start with an empty
    // ALLOWED_HOSTS anywhere else.
    if allowed.is_empty() {
        return next.run(request).await;
    }

    let host = request_host(&request).unwrap_or_default();
    if !host_allowed(host, allowed) {
        // The raw value is quoted so a control character or a spoofed host
        // cannot forge a second log line.
        tracing::warn!(target: "api", "Invalid HTTP_HOST header: {:?}", host);
        return detail_response(StatusCode::BAD_REQUEST, INVALID_HOST);
    }
    next.run(request).await
}

/// The `Host` header, or HTTP/2's `:authority` when the request carries no
/// header form of it.
fn request_host(request: &Request) -> Option<&str> {
    request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str())
        })
}

/// Django semantics: an entry of `*` allows anything, an entry beginning with
/// `.` matches that domain and its subdomains, and the comparison ignores the
/// port and is case-insensitive.
pub fn host_allowed(host: &str, allowed: &[String]) -> bool {
    let domain = split_domain(host);
    allowed
        .iter()
        .any(|pattern| pattern == "*" || is_same_domain(&domain, pattern))
}

/// Django's `split_domain_port`, minus the port it discards: lowercase the
/// host, reject anything that is not a plausible host, drop the port and a
/// single trailing dot.
fn split_domain(host: &str) -> String {
    let lowered = host.to_ascii_lowercase();
    let Some(captures) = host_validation_re().captures(&lowered) else {
        return String::new();
    };
    let domain = captures.get(1).map_or("", |value| value.as_str());
    domain.strip_suffix('.').unwrap_or(domain).to_string()
}

/// Django's `django.utils.http.is_same_domain`.
fn is_same_domain(host: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let pattern = pattern.to_ascii_lowercase();
    match pattern.strip_prefix('.') {
        Some(bare) => host.ends_with(&pattern) || host == bare,
        None => pattern == host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn hosts(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_string()).collect()
    }

    #[test]
    fn exact_entries_match_case_insensitively_and_ignore_the_port() {
        let allowed = hosts(&["example.com"]);
        for host in [
            "example.com",
            "EXAMPLE.com",
            "example.com:8080",
            "example.com.",
            "Example.Com:443",
        ] {
            assert!(host_allowed(host, &allowed), "{host}");
        }
        for host in ["other.com", "sub.example.com", "example.com.evil.com", ""] {
            assert!(!host_allowed(host, &allowed), "{host}");
        }
    }

    #[test]
    fn a_leading_dot_matches_the_domain_and_its_subdomains() {
        let allowed = hosts(&[".example.com"]);
        for host in [
            "example.com",
            "api.example.com",
            "a.b.example.com",
            "api.example.com:8080",
        ] {
            assert!(host_allowed(host, &allowed), "{host}");
        }
        for host in ["notexample.com", "example.com.evil.com", "example.org"] {
            assert!(!host_allowed(host, &allowed), "{host}");
        }
    }

    #[test]
    fn a_wildcard_entry_allows_anything_including_a_malformed_host() {
        let allowed = hosts(&["*"]);
        for host in ["example.com", "", "not a host", "::1"] {
            assert!(host_allowed(host, &allowed), "{host}");
        }
    }

    #[test]
    fn the_development_allowlist_accepts_loopback_but_nothing_else() {
        let allowed = hosts(&["127.0.0.1", "localhost"]);
        assert!(host_allowed("127.0.0.1:8080", &allowed));
        assert!(host_allowed("localhost", &allowed));
        // Django only adds these in DEBUG, and we are never in DEBUG.
        assert!(!host_allowed("[::1]", &allowed));
        assert!(!host_allowed("testserver", &allowed));
    }

    #[test]
    fn bracketed_ipv6_keeps_its_brackets_and_loses_its_port() {
        let allowed = hosts(&["[::1]"]);
        assert!(host_allowed("[::1]", &allowed));
        assert!(host_allowed("[::1]:8080", &allowed));
        // Unbracketed, it is not a valid host at all.
        assert!(!host_allowed("::1", &allowed));
    }

    #[test]
    fn malformed_hosts_never_match_a_real_entry() {
        let allowed = hosts(&["example.com", ".example.org"]);
        for host in [
            "example.com:notaport",
            "example.com:8080:9090",
            "exa_mple.com",
            "example.com/../",
            "example.com\u{2603}",
            " example.com",
        ] {
            assert!(!host_allowed(host, &allowed), "{host}");
        }
    }

    fn app(allowed: Vec<String>) -> Router {
        let allowed = Arc::new(allowed);
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |request, next| {
                let allowed = Arc::clone(&allowed);
                async move { enforce(&allowed, request, next).await }
            }))
    }

    async fn request_with_host(allowed: Vec<String>, host: Option<&str>) -> (StatusCode, String) {
        let mut builder = Request::builder().uri("/");
        if let Some(host) = host {
            builder = builder.header(header::HOST, host);
        }
        let request = builder.body(Body::empty()).expect("request builds");
        let response = app(allowed).oneshot(request).await.expect("responds");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    #[tokio::test]
    async fn an_allowed_host_passes_through() {
        let (status, body) = request_with_host(hosts(&["example.com"]), Some("example.com")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn a_disallowed_host_is_a_400_in_the_detail_envelope() {
        let (status, body) = request_with_host(hosts(&["example.com"]), Some("evil.com")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"detail":"Invalid Host Header"}"#);
    }

    #[tokio::test]
    async fn a_missing_host_header_is_rejected() {
        let (status, _) = request_with_host(hosts(&["example.com"]), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_empty_allowlist_allows_everything() {
        let (status, body) = request_with_host(Vec::new(), Some("anything.invalid")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }
}
