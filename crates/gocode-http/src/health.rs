//! Health endpoint returning agent runtime status.
//!
//! Exposes a `GET /health` endpoint that reports the current
//! `RecoveryState` and crate version. The response code mirrors
//! the state: 200 for Ready / RecoveryBlocked, 503 for
//! IntegrityBlocked / ShuttingDown.

use axum::{Router, http::StatusCode, response::Json, routing::get};
use serde::Serialize;

/// Health check response payload.
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

/// Shared read-only state passed to health handlers.
#[derive(Clone)]
pub struct HealthState {
    pub recovery_state: RecoveryState,
}

/// Agent recovery / operational state.
///
/// Mirrors the daemon-side `RecoveryState` enum known by the
/// runtime controller.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    Ready,
    RecoveryBlocked,
    IntegrityBlocked,
    ShuttingDown,
}

/// Build an Axum `Router` serving the health endpoint.
pub fn health_router(state: HealthState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .with_state(state)
}

/// Handler for `GET /health`.
async fn health_handler(
    axum::extract::State(state): axum::extract::State<HealthState>,
) -> (StatusCode, Json<HealthResponse>) {
    let (status, code) = match state.recovery_state {
        RecoveryState::Ready => ("ok", StatusCode::OK),
        RecoveryState::RecoveryBlocked => ("degraded", StatusCode::OK),
        RecoveryState::IntegrityBlocked => ("unavailable", StatusCode::SERVICE_UNAVAILABLE),
        RecoveryState::ShuttingDown => ("shutting_down", StatusCode::SERVICE_UNAVAILABLE),
    };
    (
        code,
        Json(HealthResponse {
            status,
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}
