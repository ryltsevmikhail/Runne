//! Query handlers for reading session and task-run status.
//!
//! Exposes two GET endpoints: session status and task-run status.
//! Both return stub data — real query logic will be wired to
//! the store layer in a future iteration.

use axum::{Router, extract::Path, extract::State, http::StatusCode, response::Json, routing::get};
use serde::Serialize;

// ── QueryState ──────────────────────────────────────────────────────────

/// Placeholder state for the query router.
///
/// Will hold a reference to the query / read-model store in future
/// iterations.
#[derive(Clone)]
pub struct QueryState<Q> {
    /// Placeholder for the future query store type.
    pub _phantom: std::marker::PhantomData<Q>,
}

impl<Q> QueryState<Q> {
    /// Create a new `QueryState`.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Q> Default for QueryState<Q> {
    fn default() -> Self {
        Self::new()
    }
}

// ── Response types ──────────────────────────────────────────────────────

/// Response body for session status query.
#[derive(Serialize)]
pub struct SessionStatusResponse {
    pub session_id: String,
    pub status: String,
    pub task_count: usize,
}

/// Response body for task-run status query.
#[derive(Serialize)]
pub struct TaskRunStatusResponse {
    pub taskrun_id: String,
    pub state: String,
    pub events: Vec<serde_json::Value>,
}

// ── Handlers ────────────────────────────────────────────────────────────

/// `GET /queries/session/:session_id` — read session status.
async fn session_status<Q>(
    State(_state): State<QueryState<Q>>,
    Path(session_id): Path<String>,
) -> (StatusCode, Json<SessionStatusResponse>) {
    (
        StatusCode::OK,
        Json(SessionStatusResponse {
            session_id,
            status: "active".into(),
            task_count: 0,
        }),
    )
}

/// `GET /queries/task-run/:taskrun_id` — read task-run status.
async fn task_run_status<Q>(
    State(_state): State<QueryState<Q>>,
    Path(taskrun_id): Path<String>,
) -> (StatusCode, Json<TaskRunStatusResponse>) {
    (
        StatusCode::OK,
        Json(TaskRunStatusResponse {
            taskrun_id,
            state: "created".into(),
            events: vec![],
        }),
    )
}

// ── Router ──────────────────────────────────────────────────────────────

/// Build an Axum `Router` for all query endpoints.
///
/// The router includes `with_state(QueryState::<Q>::new())` so that
/// handlers can extract `State<QueryState<Q>>`.
pub fn query_router<Q: Clone + Send + Sync + 'static>() -> Router {
    Router::new()
        .route("/queries/session/{session_id}", get(session_status::<Q>))
        .route("/queries/task-run/{taskrun_id}", get(task_run_status::<Q>))
        .with_state(QueryState::<Q>::new())
}
