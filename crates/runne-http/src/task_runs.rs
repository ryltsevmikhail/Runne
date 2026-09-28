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
    CreateTaskRunCommand, ExistingTaskRunCommand, LegacySubmitTaskRunCommand,
    MAX_CANONICAL_TERMINAL_REASON_BYTES, MAX_TASK_RUN_PROMPT_BYTES, SubmitTaskRunCommand,
    TaskRunCommandAck, TaskRunCommandAckKind, TaskRunCommandContext, TaskRunCommandHostPort,
    TaskRunHostError, TaskRunQueryHostPort, TaskRunSnapshot,
};
use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
use serde::{Deserialize, Serialize};

use crate::auth::AuthenticatedPrincipal;
use crate::error::{RequestId, canonical_error_response};

const MAX_TASK_RUN_BODY_BYTES: usize = 16 * 1024;
const MAX_TASK_RUN_SUBMIT_BODY_BYTES: usize = MAX_TASK_RUN_PROMPT_BYTES * 6 + 1024;

/// Shared state for canonical TaskRun HTTP handlers.
pub struct TaskRunHttpState<H> {
    host: Arc<H>,
    actor: ApiActor,
    pinned_model: Option<String>,
}

impl<H> Clone for TaskRunHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            actor: self.actor.clone(),
            pinned_model: self.pinned_model.clone(),
        }
    }
}

impl<H> TaskRunHttpState<H> {
    /// Wraps the canonical host, fixes the event actor for this adapter, and
    /// carries the runtime-pinned provider model for exact-model admission.
    /// `None` means the runtime has no pinned provider model.
    pub fn new(host: H, actor: ApiActor, pinned_model: Option<String>) -> Self {
        Self {
            host: Arc::new(host),
            actor,
            pinned_model,
        }
    }

    /// The provider model pinned by the runtime composition, if any.
    pub(crate) fn pinned_model(&self) -> Option<&str> {
        self.pinned_model.as_deref()
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskRunListWire {
    task_runs: Vec<TaskRunSnapshotWire>,
}

include!("task_runs/handlers.rs");
include!("task_runs/list.rs");
include!("task_runs/submit.rs");
include!("task_runs/canonical.rs");
include!("task_runs/helpers.rs");
