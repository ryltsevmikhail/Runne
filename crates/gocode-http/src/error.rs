//! Shared HTTP error type implementing `IntoResponse`.
//!
//! Converts domain / application errors into Axum responses with
//! a JSON `{"error": "…"}` body and the correct status code.

use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::Serialize;

/// Request correlation identity generated once at HTTP ingress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    /// Generates a new UUIDv7 request identity.
    pub fn generate() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }

    /// Returns the stable textual identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalErrorEnvelope<'a> {
    code: &'a str,
    request_id: &'a str,
}

/// Builds a redacted canonical JSON error and mirrors its request identity in
/// the response header.
pub fn canonical_error_response(
    status: StatusCode,
    code: &'static str,
    request_id: &RequestId,
) -> Response {
    let mut response = (
        status,
        Json(CanonicalErrorEnvelope {
            code,
            request_id: request_id.as_str(),
        }),
    )
        .into_response();
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(request_id.as_str())
            .expect("generated UUIDv7 request identity is a valid header value"),
    );
    response
}

/// Typed HTTP error variants.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.as_str()),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg.as_str()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str()),
        };
        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}
