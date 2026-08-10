//! One wallet-facing error shape: `{"detail": "<message>"}` on every 4xx/5xx.
//!
//! Port of `api/util.py`. The Python service funnels every error through
//! `normalize_error_response`, DRF's exception handler, so clients never have
//! to handle DRF's `{field: [messages]}` shape. Here the equivalent is that
//! every fallible handler returns [`ApiError`], whose `IntoResponse` writes
//! the canonical envelope.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// `validators.transaction.UpstreamServiceUnavailable.default_detail`.
const UPSTREAM_DETAIL: &str = "Validation Service Unavailable";
/// `services.collateral.SigningServiceUnavailable.default_detail`.
const SIGNING_DETAIL: &str = "Signing Service Unavailable";

/// Every error the API can return, carrying its own status code.
#[derive(Debug, Clone)]
pub enum ApiError {
    /// 400 — the caller sent something we will not sign. Logged at WARN by
    /// [`ApiError::validation`], matching `util.raise_validation_error`.
    Validation(String),
    /// 503 — `validators.transaction.UpstreamServiceUnavailable`.
    Upstream,
    /// 503 — `services.collateral.SigningServiceUnavailable`.
    Signing,
    /// Any other status with an explicit detail string.
    Status { status: StatusCode, detail: String },
}

impl ApiError {
    /// Log at WARNING and build a 400.
    ///
    /// Logged at WARNING because these are *user* errors (the client sent us
    /// something we won't sign), not server errors. Reserve ERROR for things
    /// that page the on-call.
    pub fn validation(message: impl Into<String>) -> Self {
        let message = message.into();
        // Target "api" so the record carries the same logger name the Python
        // service uses; the message is the whole line there, so no fields.
        tracing::warn!(target: "api", "{}", message);
        ApiError::Validation(message)
    }

    /// Build an error with an explicit status code and detail string.
    pub fn status(status: StatusCode, detail: impl Into<String>) -> Self {
        ApiError::Status {
            status,
            detail: detail.into(),
        }
    }

    /// The HTTP status this error serializes to.
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::Validation(_) => StatusCode::BAD_REQUEST,
            ApiError::Upstream | ApiError::Signing => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Status { status, .. } => *status,
        }
    }

    /// The `detail` string this error serializes to.
    pub fn detail(&self) -> &str {
        match self {
            ApiError::Validation(message) => message,
            ApiError::Upstream => UPSTREAM_DETAIL,
            ApiError::Signing => SIGNING_DETAIL,
            ApiError::Status { detail, .. } => detail,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail())
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        detail_response(self.status_code(), self.detail())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// Build the canonical `{"detail": ...}` body for a status code.
pub fn detail_response(status: StatusCode, detail: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "detail": detail }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("body is JSON")
    }

    #[test]
    fn validation_is_a_400_carrying_its_message() {
        let err = ApiError::validation("Tx Is Too Large");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(err.detail(), "Tx Is Too Large");
        assert_eq!(err.to_string(), "Tx Is Too Large");
    }

    #[test]
    fn upstream_and_signing_are_503_with_fixed_details() {
        assert_eq!(
            ApiError::Upstream.status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ApiError::Upstream.detail(),
            "Validation Service Unavailable"
        );
        assert_eq!(
            ApiError::Signing.status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(ApiError::Signing.detail(), "Signing Service Unavailable");
    }

    #[test]
    fn explicit_status_round_trips() {
        let err = ApiError::status(StatusCode::TOO_MANY_REQUESTS, "Request Was Throttled");
        assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.detail(), "Request Was Throttled");
    }

    #[tokio::test]
    async fn every_error_serializes_to_the_detail_envelope() {
        for err in [
            ApiError::Validation("Invalid Environment: nope".into()),
            ApiError::Upstream,
            ApiError::Signing,
            ApiError::status(StatusCode::NOT_FOUND, "Not Found"),
        ] {
            let expected = err.detail().to_string();
            let status = err.status_code();
            let response = err.into_response();
            assert_eq!(response.status(), status);
            let body = body_json(response).await;
            // Exactly one key: a wallet parsing `detail` must never also have
            // to handle DRF's `{field: [messages]}` shape.
            assert_eq!(body.as_object().map(|o| o.len()), Some(1));
            assert_eq!(body["detail"], serde_json::json!(expected));
        }
    }

    #[tokio::test]
    async fn detail_response_sets_json_content_type() {
        let response = detail_response(StatusCode::BAD_REQUEST, "Invalid Host Header");
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = body_json(response).await;
        assert_eq!(body["detail"], serde_json::json!("Invalid Host Header"));
    }
}
