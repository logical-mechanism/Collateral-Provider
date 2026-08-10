//! Tag every request with an `X-Request-ID` for log correlation.
//!
//! If the client supplies a safe value we honor it (so they can grep the same
//! id across our logs and theirs). Otherwise we mint 12 hex characters. The id
//! is stored in a task-local so the logging layer can pick it up from any code
//! path the request touches.
//!
//! Request IDs are reflected in a response header and appear in every log
//! record, so client-supplied values are restricted to a conservative ASCII
//! alphabet — they cannot inject control characters or structured-log
//! delimiters. This still accepts UUIDs, W3C traceparent values, and the
//! common `service:id` / `service.id` forms. An invalid or overlong value is
//! never truncated into something that might collide with a legitimate
//! caller's id; a fresh local id is minted instead.

use axum::extract::Request;
use axum::http::header::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::logging::REQUEST_ID;

pub const HEADER: &str = "x-request-id";
pub const MAX_INCOMING_LEN: usize = 64;

pub async fn middleware(request: Request, next: Next) -> Response {
    // A non-ASCII header value fails `to_str`, which is the same verdict the
    // Python `re.ASCII` alphabet reaches.
    let incoming = request
        .headers()
        .get(HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default();
    let request_id = if is_safe_request_id(incoming) {
        incoming.to_string()
    } else {
        mint_request_id()
    };

    // The scope has to wrap the handler, not just precede it, so every record
    // the request produces carries the id.
    let mut response = REQUEST_ID
        .scope(request_id.clone(), next.run(request))
        .await;
    // Only ever a hex string or a value that passed the alphabet check, so
    // this cannot fail; skipping the header beats panicking if it somehow can.
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(HEADER), value);
    }
    response
}

/// Whether a client-supplied request id may be echoed back.
pub fn is_safe_request_id(value: &str) -> bool {
    // The alphabet is ASCII-only, so byte length is character length for
    // anything that gets this far.
    if value.is_empty() || value.len() > MAX_INCOMING_LEN {
        return false;
    }
    let mut characters = value.chars();
    let leading_ok = characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric());
    leading_ok
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
        })
}

/// `uuid4().hex[:12]` in the Python service: 12 hex characters of entropy.
fn mint_request_id() -> String {
    format!("{:012x}", rand::random::<u64>() & 0xffff_ffff_ffff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/", get(|| async { crate::logging::current_request_id() }))
            .layer(axum::middleware::from_fn(middleware))
    }

    async fn header_for(incoming: Option<&str>) -> String {
        let mut builder = Request::builder().uri("/");
        if let Some(incoming) = incoming {
            builder = builder.header(HEADER, incoming);
        }
        let request = builder.body(Body::empty()).expect("request builds");
        let response = app().oneshot(request).await.expect("service responds");
        response
            .headers()
            .get(HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    fn is_minted(value: &str) -> bool {
        value.len() == 12
            && value
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    }

    #[tokio::test]
    async fn mints_twelve_hex_characters_without_a_client_header() {
        let id = header_for(None).await;
        assert!(is_minted(&id), "{id}");
    }

    #[tokio::test]
    async fn honors_a_safe_client_header() {
        assert_eq!(header_for(Some("trace-abc-123")).await, "trace-abc-123");
    }

    #[tokio::test]
    async fn replaces_an_overlong_client_header_without_truncating_it() {
        // Two long ids sharing a prefix must not collapse into one
        // operator-visible correlation id.
        let long = "x".repeat(5000);
        let id = header_for(Some(&long)).await;
        assert!(is_minted(&id), "{id}");
        assert_ne!(id, long[..12]);
    }

    #[tokio::test]
    async fn accepts_a_safe_id_at_the_maximum_length() {
        let tail: String = "Z9._:-"
            .repeat(11)
            .chars()
            .take(MAX_INCOMING_LEN - 1)
            .collect();
        let incoming = format!("a{tail}");
        assert_eq!(incoming.len(), MAX_INCOMING_LEN);
        assert_eq!(header_for(Some(&incoming)).await, incoming);
    }

    #[tokio::test]
    async fn a_blank_header_is_treated_as_missing() {
        let id = header_for(Some("   ")).await;
        assert!(is_minted(&id), "{id}");
    }

    #[tokio::test]
    async fn the_id_is_visible_to_the_handler_and_cleared_afterwards() {
        let request = Request::builder()
            .uri("/")
            .header(HEADER, "trace-abc-123")
            .body(Body::empty())
            .expect("request builds");
        let response = app().oneshot(request).await.expect("service responds");
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body collects")
            .to_bytes();
        assert_eq!(&body[..], b"trace-abc-123");
        assert_eq!(crate::logging::current_request_id(), "-");
    }

    #[test]
    fn unsafe_alphabets_are_rejected() {
        for value in [
            "",
            "   ",
            "trace-ok\nWARNING forged-log-entry",
            "trace\"fake\":true",
            "trace/../../etc",
            "trace-\u{2603}",
            "-leading-punctuation",
            ".dotted",
            "has space",
            &"x".repeat(MAX_INCOMING_LEN + 1),
        ] {
            assert!(!is_safe_request_id(value), "{value:?} accepted");
        }
    }

    #[test]
    fn common_correlation_id_shapes_are_accepted() {
        for value in [
            "0af7651916cd43dd8448eb211c80319c",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "service:12345",
            "service.12345",
            "A1",
            "9",
        ] {
            assert!(is_safe_request_id(value), "{value:?} rejected");
        }
    }
}
