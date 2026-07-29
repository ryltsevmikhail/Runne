//! Shared HTTP error type implementing `IntoResponse`.
//!
//! Converts domain / application errors into Axum responses with
//! a JSON `{"error": "…"}` body and the correct status code.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};

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
