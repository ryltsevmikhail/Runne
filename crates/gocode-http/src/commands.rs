//! Command handlers for session and task-run lifecycle.
//!
//! Exposes five POST endpoints: create-session, prompt, abort,
//! create-task-run, complete-task-run. All return 202 Accepted
//! with stub data — real execution logic will be added later.

use axum::{Router, extract::State, http::StatusCode, response::Json, routing::post};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── CommandState ────────────────────────────────────────────────────────

/// Placeholder state for the command router.
///
/// Will hold a reference to the command executor in future iterations.
#[derive(Clone)]
pub struct CommandState<C> {
    /// Placeholder for the future command executor type.
    pub _phantom: std::marker::PhantomData<C>,
}

impl<C> CommandState<C> {
    /// Create a new `CommandState`.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<C> Default for CommandState<C> {
    fn default() -> Self {
        Self::new()
    }
}

// ── Request / Response types ────────────────────────────────────────────

/// Request body for creating a new agent session.
#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub workspace_id: String,
    pub profile_id: Option<String>,
}

/// Response body for a newly created session.
#[derive(Serialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub status: String,
}

/// Request body for sending a prompt to an active session.
#[derive(Deserialize)]
pub struct PromptRequest {
    pub message: String,
    pub attachments: Option<Vec<String>>,
}

/// Response body after accepting a prompt.
#[derive(Serialize)]
pub struct PromptResponse {
    pub taskrun_id: String,
    pub status: String,
}

/// Request body for aborting an active session.
#[derive(Deserialize)]
pub struct AbortRequest {
    pub reason: Option<String>,
}

/// Response body after aborting a session.
#[derive(Serialize)]
pub struct AbortResponse {
    pub status: String,
}

/// Request body for creating a standalone task run.
#[derive(Deserialize)]
pub struct CreateTaskRunRequest {
    pub task_type: String,
    pub input: serde_json::Value,
}

/// Response body for a newly created task run.
#[derive(Serialize)]
pub struct CreateTaskRunResponse {
    pub taskrun_id: String,
}

/// Request body for completing a task run.
#[derive(Deserialize)]
pub struct CompleteTaskRunRequest {
    pub outcome: String,
    pub output: Option<serde_json::Value>,
}

/// Response body after completing a task run.
#[derive(Serialize)]
pub struct CompleteTaskRunResponse {
    pub taskrun_id: String,
    pub status: String,
}

// ── Handlers ────────────────────────────────────────────────────────────

/// `POST /commands/create-session` — start a new agent session.
async fn create_session<C>(
    State(_state): State<CommandState<C>>,
    Json(_req): Json<CreateSessionRequest>,
) -> (StatusCode, Json<CreateSessionResponse>) {
    (
        StatusCode::ACCEPTED,
        Json(CreateSessionResponse {
            session_id: Uuid::now_v7().to_string(),
            status: "created".into(),
        }),
    )
}

/// `POST /commands/prompt` — send a prompt to an existing session.
async fn send_prompt<C>(
    State(_state): State<CommandState<C>>,
    Json(_req): Json<PromptRequest>,
) -> (StatusCode, Json<PromptResponse>) {
    (
        StatusCode::ACCEPTED,
        Json(PromptResponse {
            taskrun_id: Uuid::now_v7().to_string(),
            status: "accepted".into(),
        }),
    )
}

/// `POST /commands/abort` — abort an active session.
async fn abort_session<C>(
    State(_state): State<CommandState<C>>,
    Json(_req): Json<AbortRequest>,
) -> (StatusCode, Json<AbortResponse>) {
    (
        StatusCode::ACCEPTED,
        Json(AbortResponse {
            status: "aborted".into(),
        }),
    )
}

/// `POST /commands/create-task-run` — create a standalone task run.
async fn create_task_run<C>(
    State(_state): State<CommandState<C>>,
    Json(_req): Json<CreateTaskRunRequest>,
) -> (StatusCode, Json<CreateTaskRunResponse>) {
    (
        StatusCode::ACCEPTED,
        Json(CreateTaskRunResponse {
            taskrun_id: Uuid::now_v7().to_string(),
        }),
    )
}

/// `POST /commands/complete-task-run` — mark a task run as complete.
async fn complete_task_run<C>(
    State(_state): State<CommandState<C>>,
    Json(_req): Json<CompleteTaskRunRequest>,
) -> (StatusCode, Json<CompleteTaskRunResponse>) {
    (
        StatusCode::ACCEPTED,
        Json(CompleteTaskRunResponse {
            taskrun_id: Uuid::now_v7().to_string(),
            status: "completed".into(),
        }),
    )
}

// ── Router ──────────────────────────────────────────────────────────────

/// Build an Axum `Router` for all command endpoints.
///
/// The router includes `with_state(CommandState::<C>::new())` so that
/// handlers can extract `State<CommandState<C>>`.
pub fn command_router<C: Clone + Send + Sync + 'static>() -> Router {
    Router::new()
        .route("/commands/create-session", post(create_session::<C>))
        .route("/commands/prompt", post(send_prompt::<C>))
        .route("/commands/abort", post(abort_session::<C>))
        .route("/commands/create-task-run", post(create_task_run::<C>))
        .route("/commands/complete-task-run", post(complete_task_run::<C>))
        .with_state(CommandState::<C>::new())
}
