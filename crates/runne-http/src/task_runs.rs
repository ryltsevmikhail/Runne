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
    SupersedeUnknownTaskRunCommand, TaskRunCommandAck, TaskRunCommandAckKind,
    TaskRunCommandContext, TaskRunCommandHostPort, TaskRunEffectsV1, TaskRunHostError,
    TaskRunQueryHostPort, TaskRunSnapshot, UnknownSuccessorAcknowledgment,
};
use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
use serde::{Deserialize, Serialize};

mod routes;
#[cfg(feature = "test-support")]
pub mod test_support;
pub use routes::task_run_router;

use crate::auth::AuthenticatedPrincipal;
use crate::error::{RequestId, canonical_error_response};

const MAX_TASK_RUN_BODY_BYTES: usize = 16 * 1024;
const MAX_TASK_RUN_SUBMIT_BODY_BYTES: usize = MAX_TASK_RUN_PROMPT_BYTES * 6 + 1024;

/// Shared state for canonical TaskRun HTTP handlers.
pub struct TaskRunHttpState<H> {
    host: Arc<H>,
    actor: ApiActor,
    pinned_model: Option<String>,
    allowed_profiles: Vec<runne_domain::task_run::SelectedProviderProfile>,
    profile_models: Vec<(runne_domain::task_run::SelectedProviderProfile, String)>,
    prohibited_content:
        Option<Arc<dyn runne_application::prohibited_content::ProhibitedContentPort>>,
}

impl<H> Clone for TaskRunHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            actor: self.actor.clone(),
            pinned_model: self.pinned_model.clone(),
            allowed_profiles: self.allowed_profiles.clone(),
            profile_models: self.profile_models.clone(),
            prohibited_content: self.prohibited_content.clone(),
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
            allowed_profiles: Vec::new(),
            profile_models: Vec::new(),
            prohibited_content: None,
        }
    }

    /// The provider model pinned by the runtime composition, if any.
    pub(crate) fn pinned_model(&self) -> Option<&str> {
        self.pinned_model.as_deref()
    }

    /// Adds server-authorized immutable profile tuples for explicit submits.
    pub fn with_allowed_profiles(
        mut self,
        profiles: Vec<runne_domain::task_run::SelectedProviderProfile>,
    ) -> Self {
        self.allowed_profiles = profiles;
        self
    }

    /// Adds exact runtime-pinned model IDs for the corresponding profile tuples.
    pub fn with_profile_models(
        mut self,
        models: Vec<(runne_domain::task_run::SelectedProviderProfile, String)>,
    ) -> Self {
        self.profile_models = models;
        self
    }

    /// Installs the canonical-content guard used before typed command input is stored.
    pub fn with_prohibited_content(
        mut self,
        guard: Arc<dyn runne_application::prohibited_content::ProhibitedContentPort>,
    ) -> Self {
        self.prohibited_content = Some(guard);
        self
    }

    pub(crate) fn profile_is_allowed(
        &self,
        candidate: &runne_domain::task_run::SelectedProviderProfile,
    ) -> bool {
        self.allowed_profiles
            .iter()
            .any(|allowed| allowed == candidate)
    }

    pub(crate) fn model_for_profile(
        &self,
        profile: Option<&runne_domain::task_run::SelectedProviderProfile>,
    ) -> Option<&str> {
        match profile {
            None => self.pinned_model(),
            Some(profile) => self
                .profile_models
                .iter()
                .find(|(allowed, _)| allowed == profile)
                .map(|(_, model)| model.as_str()),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_task_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_version: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskRunSnapshotWire {
    task_run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_id: Option<String>,
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
include!("task_runs/effects.rs");
include!("task_runs/tool_activity.rs");
include!("task_runs/list.rs");
include!("task_runs/submit.rs");
include!("task_runs/submit_guard.rs");
include!("task_runs/successor.rs");
include!("task_runs/canonical.rs");
include!("task_runs/helpers.rs");
