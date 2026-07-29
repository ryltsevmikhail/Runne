//! Strict authenticated HTTP projection of the canonical TaskRun API.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use gocode_api::{
    ApiActor, CanonicalTaskRunState, CanonicalTerminalResult, CompleteTaskRunCommand,
    CreateTaskRunCommand, ExistingTaskRunCommand, MAX_CANONICAL_TERMINAL_REASON_BYTES,
    TaskRunCommandAck, TaskRunCommandAckKind, TaskRunCommandContext, TaskRunCommandHostPort,
    TaskRunHostError, TaskRunQueryHostPort, TaskRunSnapshot,
};
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
use serde::{Deserialize, Serialize};

use crate::auth::AuthenticatedPrincipal;
use crate::error::{RequestId, canonical_error_response};

const MAX_TASK_RUN_BODY_BYTES: usize = 16 * 1024;

/// Shared state for canonical TaskRun HTTP handlers.
pub struct TaskRunHttpState<H> {
    host: Arc<H>,
    actor: ApiActor,
}

impl<H> Clone for TaskRunHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            actor: self.actor.clone(),
        }
    }
}

impl<H> TaskRunHttpState<H> {
    /// Wraps the canonical host and fixes the event actor for this adapter.
    pub fn new(host: H, actor: ApiActor) -> Self {
        Self {
            host: Arc::new(host),
            actor,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateTaskRunBody {
    conversation_id: String,
    workspace_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExistingTaskRunBody {
    expected_version: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TerminalResultWire {
    Success,
    Failure { reason: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompleteTaskRunBody {
    expected_version: u64,
    result: TerminalResultWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskRunAckWire {
    task_run_id: String,
    stream_version: u64,
    transition: &'static str,
    attempt_id: Option<String>,
    terminal_result: Option<TerminalResultWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskRunSnapshotWire {
    task_run_id: String,
    state: &'static str,
    stream_version: u64,
    active_attempt_id: Option<String>,
    terminal_result: Option<TerminalResultWire>,
}

/// Builds the real canonical TaskRun route set.
pub fn task_run_router<H>(state: TaskRunHttpState<H>) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    Router::new()
        .route("/v1/task-runs", post(create_task_run::<H>))
        .route("/v1/task-runs/{taskrun_id}", get(get_task_run::<H>))
        .route(
            "/v1/task-runs/{taskrun_id}/queue",
            post(queue_task_run::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/admit",
            post(admit_task_run::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/attempts",
            post(start_attempt::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/complete",
            post(complete_task_run::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_TASK_RUN_BODY_BYTES))
        .with_state(state)
}

async fn create_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Json<CreateTaskRunBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(context) => context,
        Err(code) => return bad_request(code, &request_id),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let conversation_id = match body.conversation_id.parse::<ConversationId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_conversation_id", &request_id),
    };
    let workspace_id = match body.workspace_id.parse::<WorkspaceId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_workspace_id", &request_id),
    };

    command_response(
        state
            .host
            .create_task_run(
                context,
                CreateTaskRunCommand {
                    conversation_id,
                    workspace_id,
                },
            )
            .await,
        &request_id,
    )
}

async fn queue_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ExistingTaskRunBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    existing_command(
        state,
        principal,
        request_id,
        taskrun_id,
        headers,
        body,
        ExistingOperation::Queue,
    )
    .await
}

async fn admit_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ExistingTaskRunBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    existing_command(
        state,
        principal,
        request_id,
        taskrun_id,
        headers,
        body,
        ExistingOperation::Admit,
    )
    .await
}

async fn start_attempt<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ExistingTaskRunBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    existing_command(
        state,
        principal,
        request_id,
        taskrun_id,
        headers,
        body,
        ExistingOperation::StartAttempt,
    )
    .await
}

#[derive(Clone, Copy)]
enum ExistingOperation {
    Queue,
    Admit,
    StartAttempt,
}

#[allow(clippy::too_many_arguments)]
async fn existing_command<H>(
    state: TaskRunHttpState<H>,
    principal: AuthenticatedPrincipal,
    request_id: RequestId,
    taskrun_id: String,
    headers: HeaderMap,
    body: Result<Json<ExistingTaskRunBody>, JsonRejection>,
    operation: ExistingOperation,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(context) => context,
        Err(code) => return bad_request(code, &request_id),
    };
    let taskrun_id = match taskrun_id.parse::<TaskRunId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_task_run_id", &request_id),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let command = ExistingTaskRunCommand {
        taskrun_id,
        expected_version: body.expected_version,
    };
    let result = match operation {
        ExistingOperation::Queue => state.host.queue_task_run(context, command).await,
        ExistingOperation::Admit => state.host.admit_task_run(context, command).await,
        ExistingOperation::StartAttempt => state.host.start_attempt(context, command).await,
    };
    command_response(result, &request_id)
}

async fn complete_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<CompleteTaskRunBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(context) => context,
        Err(code) => return bad_request(code, &request_id),
    };
    let taskrun_id = match taskrun_id.parse::<TaskRunId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_task_run_id", &request_id),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let result = match body.result {
        TerminalResultWire::Success => CanonicalTerminalResult::Success,
        TerminalResultWire::Failure { reason } => {
            if reason.len() > MAX_CANONICAL_TERMINAL_REASON_BYTES {
                return bad_request("invalid_terminal_reason", &request_id);
            }
            CanonicalTerminalResult::Failure { reason }
        }
    };

    command_response(
        state
            .host
            .complete_task_run(
                context,
                CompleteTaskRunCommand {
                    taskrun_id,
                    expected_version: body.expected_version,
                    result,
                },
            )
            .await,
        &request_id,
    )
}

async fn get_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    let taskrun_id = match taskrun_id.parse::<TaskRunId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_task_run_id", &request_id),
    };
    match state.host.get_task_run(taskrun_id).await {
        Ok(snapshot) => (StatusCode::OK, Json(snapshot_to_wire(snapshot))).into_response(),
        Err(error) => host_error_response(error, &request_id),
    }
}

fn command_context(
    headers: &HeaderMap,
    principal: &AuthenticatedPrincipal,
    actor: &ApiActor,
) -> Result<TaskRunCommandContext, &'static str> {
    let command_id = exactly_one_header(headers, "x-command-id")
        .and_then(|value| value.parse::<CommandId>().ok())
        .ok_or("invalid_command_id")?;
    let idempotency_key = exactly_one_header(headers, "idempotency-key")
        .and_then(|value| IdempotencyKey::new(value).ok())
        .ok_or("invalid_idempotency_key")?;
    Ok(TaskRunCommandContext {
        command_id,
        idempotency_key,
        principal: principal.as_api_principal().clone(),
        actor: actor.clone(),
    })
}

fn exactly_one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn command_response(
    result: Result<TaskRunCommandAck, TaskRunHostError>,
    request_id: &RequestId,
) -> Response {
    match result {
        Ok(ack) => (StatusCode::ACCEPTED, Json(ack_to_wire(ack))).into_response(),
        Err(error) => host_error_response(error, request_id),
    }
}

fn ack_to_wire(ack: TaskRunCommandAck) -> TaskRunAckWire {
    let (transition, attempt_id, terminal_result) = match ack.kind {
        TaskRunCommandAckKind::Created => ("created", None, None),
        TaskRunCommandAckKind::Queued => ("queued", None, None),
        TaskRunCommandAckKind::Admitted => ("admitted", None, None),
        TaskRunCommandAckKind::AttemptStarted { attempt_id } => {
            ("attempt_started", Some(attempt_id.to_string()), None)
        }
        TaskRunCommandAckKind::Completed { result } => {
            ("completed", None, Some(terminal_result_to_wire(result)))
        }
    };
    TaskRunAckWire {
        task_run_id: ack.taskrun_id.to_string(),
        stream_version: ack.new_version,
        transition,
        attempt_id,
        terminal_result,
    }
}

fn snapshot_to_wire(snapshot: TaskRunSnapshot) -> TaskRunSnapshotWire {
    TaskRunSnapshotWire {
        task_run_id: snapshot.taskrun_id.to_string(),
        state: state_name(snapshot.state),
        stream_version: snapshot.stream_version,
        active_attempt_id: snapshot.active_attempt_id.map(|id| id.to_string()),
        terminal_result: snapshot.terminal_result.map(terminal_result_to_wire),
    }
}

fn state_name(state: CanonicalTaskRunState) -> &'static str {
    state.as_str()
}

fn terminal_result_to_wire(result: CanonicalTerminalResult) -> TerminalResultWire {
    match result {
        CanonicalTerminalResult::Success => TerminalResultWire::Success,
        CanonicalTerminalResult::Failure { reason } => TerminalResultWire::Failure { reason },
    }
}

fn host_error_response(error: TaskRunHostError, request_id: &RequestId) -> Response {
    let status = match error {
        TaskRunHostError::NotFound => StatusCode::NOT_FOUND,
        TaskRunHostError::Conflict => StatusCode::CONFLICT,
        TaskRunHostError::Backpressure | TaskRunHostError::Unavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        TaskRunHostError::InvariantViolation => StatusCode::INTERNAL_SERVER_ERROR,
    };
    canonical_error_response(status, error.code(), request_id)
}

fn bad_request(code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(StatusCode::BAD_REQUEST, code, request_id)
}
