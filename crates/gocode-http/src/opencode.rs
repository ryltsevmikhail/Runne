//! Strict HTTP projection of the pinned OpenCode V1 session compatibility API.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use gocode_opencode_compat::{
    OpenCodeSessionV1Service, SessionV1Error, SessionV1HostError, SessionV1HostPort,
};

/// Shared compatibility service state.
pub struct OpenCodeSessionState<H: SessionV1HostPort> {
    service: Arc<OpenCodeSessionV1Service<H>>,
}

impl<H: SessionV1HostPort> Clone for OpenCodeSessionState<H> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
        }
    }
}

impl<H: SessionV1HostPort> OpenCodeSessionState<H> {
    /// Wraps a strict compatibility service for HTTP routing.
    pub fn new(service: OpenCodeSessionV1Service<H>) -> Self {
        Self {
            service: Arc::new(service),
        }
    }
}

/// Builds the four pinned Phase 8 session routes.
///
/// Authentication, request identity and admission middleware are deliberately
/// composed by the parent router, exactly like the canonical command routes.
pub fn opencode_session_router<H>(state: OpenCodeSessionState<H>) -> Router
where
    H: SessionV1HostPort + 'static,
{
    Router::new()
        .route("/session/status", get(status::<H>))
        .route("/session/{session_id}/message", post(prompt::<H>))
        .route(
            "/session/{session_id}/prompt_async",
            post(prompt_async::<H>),
        )
        .route("/session/{session_id}/abort", post(abort::<H>))
        .with_state(state)
}

async fn prompt<H: SessionV1HostPort>(
    State(state): State<OpenCodeSessionState<H>>,
    Path(session_id): Path<String>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return wire_error(StatusCode::BAD_REQUEST, "invalid_json"),
    };
    match state.service.prompt(&session_id, body).await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => compatibility_error(error),
    }
}

async fn prompt_async<H: SessionV1HostPort>(
    State(state): State<OpenCodeSessionState<H>>,
    Path(session_id): Path<String>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return wire_error(StatusCode::BAD_REQUEST, "invalid_json"),
    };
    match state.service.prompt_async(&session_id, body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => compatibility_error(error),
    }
}

async fn status<H: SessionV1HostPort>(State(state): State<OpenCodeSessionState<H>>) -> Response {
    match state.service.status().await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => compatibility_error(error),
    }
}

async fn abort<H: SessionV1HostPort>(
    State(state): State<OpenCodeSessionState<H>>,
    Path(session_id): Path<String>,
) -> Response {
    match state.service.abort(&session_id).await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => compatibility_error(error),
    }
}

fn compatibility_error(error: SessionV1Error) -> Response {
    match error {
        SessionV1Error::InvalidSessionId | SessionV1Error::InvalidRequest { .. } => {
            wire_error(StatusCode::BAD_REQUEST, "invalid_request")
        }
        SessionV1Error::UnsupportedField { .. } | SessionV1Error::UnsupportedPart { .. } => {
            wire_error(StatusCode::UNPROCESSABLE_ENTITY, "unsupported")
        }
        SessionV1Error::HostOutputMismatch => {
            wire_error(StatusCode::BAD_GATEWAY, "host_output_mismatch")
        }
        SessionV1Error::Host(SessionV1HostError::NotFound) => {
            wire_error(StatusCode::NOT_FOUND, "not_found")
        }
        SessionV1Error::Host(SessionV1HostError::Conflict) => {
            wire_error(StatusCode::CONFLICT, "conflict")
        }
        SessionV1Error::Host(SessionV1HostError::StorageFailure) => {
            wire_error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
        }
        SessionV1Error::Host(SessionV1HostError::Timeout) => {
            wire_error(StatusCode::GATEWAY_TIMEOUT, "timeout")
        }
    }
}

fn wire_error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({"error": code}))).into_response()
}
