//! Replay HTTP handlers for event sourcing session replay.
//!
//! Exposes five POST endpoints: open-session, read-page, complete-catch-up,
//! continue-live, close. All handlers are stubs — real implementations
//! require integration with ReplayService.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::post;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::HttpError;
use crate::limits::LimitsConfig;

// ── ReplayState ──────────────────────────────────────────────────────────

/// Replay state, passed to handlers.
#[derive(Clone)]
pub struct ReplayState<R> {
    pub service: Arc<R>,
    pub limits: LimitsConfig,
}

// ── Opaque reference types ───────────────────────────────────────────────

/// Opaque reference types (simplified — real impl uses HMAC-protected blobs).
pub type SessionId = String;
pub type HighWaterRef = String;
pub type CatchUpProof = String;
pub type LiveDeliveryId = String;

// ── Request / Response types ─────────────────────────────────────────────

#[derive(Serialize)]
pub struct OpenSessionResponse {
    pub session_id: SessionId,
    pub high_water_ref: HighWaterRef,
    pub events: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct OpenSessionRequest {
    pub principal_id: String,
    pub session_generation: i64,
    pub authority_id: String,
    pub authorization_epoch: i64,
    pub aggregate_type: i32,
    pub aggregate_id: String,
}

#[derive(Serialize)]
pub struct ReadPageResponse {
    pub events: Vec<serde_json::Value>,
    pub has_more: bool,
}

#[derive(Deserialize)]
pub struct ReadPageRequest {
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct CompleteCatchUpResponse {
    pub catch_up_proof: CatchUpProof,
    pub session_state: String,
}

#[derive(Serialize)]
pub struct ContinueLiveResponse {
    pub live_delivery_id: LiveDeliveryId,
    pub session_state: String,
}

#[derive(Deserialize)]
pub struct CompleteCatchUpRequest {
    pub catch_up_proof: String,
}

// ── Handlers ─────────────────────────────────────────────────────────────

/// `POST /replay/open-session` — open a new replay session.
async fn open_session<R>(
    State(_state): State<ReplayState<R>>,
    Json(_req): Json<OpenSessionRequest>,
) -> Result<(StatusCode, Json<OpenSessionResponse>), HttpError> {
    Ok((
        StatusCode::OK,
        Json(OpenSessionResponse {
            session_id: uuid::Uuid::now_v7().to_string(),
            high_water_ref: "hw-ref-placeholder".into(),
            events: vec![],
        }),
    ))
}

/// `POST /replay/{session_id}/read-page` — read a page of events from the replay session.
async fn read_page<R>(
    State(_state): State<ReplayState<R>>,
    Path(_session_id): Path<String>,
    Json(_req): Json<ReadPageRequest>,
) -> Result<(StatusCode, Json<ReadPageResponse>), HttpError> {
    Ok((
        StatusCode::OK,
        Json(ReadPageResponse {
            events: vec![],
            has_more: false,
        }),
    ))
}

/// `POST /replay/{session_id}/complete-catch-up` — complete the catch-up phase.
async fn complete_catch_up<R>(
    State(_state): State<ReplayState<R>>,
    Path(_session_id): Path<String>,
    Json(_req): Json<CompleteCatchUpRequest>,
) -> Result<(StatusCode, Json<CompleteCatchUpResponse>), HttpError> {
    Ok((
        StatusCode::OK,
        Json(CompleteCatchUpResponse {
            catch_up_proof: "proof-placeholder".into(),
            session_state: "catch_up_complete".into(),
        }),
    ))
}

/// `POST /replay/{session_id}/continue-live` — continue to live delivery.
async fn continue_live<R>(
    State(_state): State<ReplayState<R>>,
    Path(_session_id): Path<String>,
) -> Result<(StatusCode, Json<ContinueLiveResponse>), HttpError> {
    Ok((
        StatusCode::OK,
        Json(ContinueLiveResponse {
            live_delivery_id: "live-id-placeholder".into(),
            session_state: "live".into(),
        }),
    ))
}

/// `POST /replay/{session_id}/close` — close a replay session.
async fn close_session<R>(
    State(_state): State<ReplayState<R>>,
    Path(_session_id): Path<String>,
) -> Result<StatusCode, HttpError> {
    Ok(StatusCode::NO_CONTENT)
}

// ── Router ───────────────────────────────────────────────────────────────

/// Build an Axum `Router` for all replay endpoints.
///
/// The router includes `with_state(state)` so that handlers can
/// extract `State<ReplayState<R>>`.
pub fn replay_router<R: Clone + Send + Sync + 'static>(state: ReplayState<R>) -> Router {
    Router::new()
        .route("/replay/open-session", post(open_session::<R>))
        .route("/replay/{session_id}/read-page", post(read_page::<R>))
        .route(
            "/replay/{session_id}/complete-catch-up",
            post(complete_catch_up::<R>),
        )
        .route(
            "/replay/{session_id}/continue-live",
            post(continue_live::<R>),
        )
        .route("/replay/{session_id}/close", post(close_session::<R>))
        .with_state(state)
}
