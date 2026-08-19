//! Strict authenticated HTTP projection of the canonical TaskRun API.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use runne_api::{
    ApiActor, CanonicalTaskRunState, CanonicalTerminalResult, CompleteTaskRunCommand,
    CreateTaskRunCommand, ExistingTaskRunCommand, MAX_CANONICAL_TERMINAL_REASON_BYTES,
    TaskRunCommandAck, TaskRunCommandAckKind, TaskRunCommandContext, TaskRunCommandHostPort,
    TaskRunHostError, TaskRunQueryHostPort, TaskRunSnapshot,
};
use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
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

include!("task_runs/handlers.rs");
include!("task_runs/helpers.rs");
