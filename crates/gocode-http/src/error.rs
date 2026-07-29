//! Redacted canonical HTTP error envelope and ingress request identity.

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
