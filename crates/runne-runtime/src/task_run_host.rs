//! Canonical TaskRun host backed by the runtime command path and event store.

use runne_api::{
    CanonicalTaskRunState, CanonicalTerminalResult, CompleteTaskRunCommand, CreateTaskRunCommand,
    ExistingTaskRunCommand, LegacySubmitTaskRunCommand, SubmitTaskRunCommand,
    SupersedeUnknownTaskRunCommand, TaskRunCommandAck, TaskRunCommandAckKind,
    TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError, TaskRunQueryHostPort,
    TaskRunSnapshot, UnknownSuccessorAcknowledgment,
};
use runne_application::commands::{
    AdmitTaskRunInput, CancelTaskRunInput, CommandOutcome, CompleteTaskRunInput,
    CreateTaskRunInput, LegacySubmitTaskRunInput, QueueTaskRunInput, StartAttemptInput,
    SubmitTaskRunInput, SupersedeUnknownTaskRunInput,
};
use runne_application::errors::ApplicationError;
use runne_application::ports::{
    ApplicationCommandContext, EventStore, EventStoreError, PrincipalId,
};
use runne_domain::command::TerminalResult;
use runne_domain::error::DomainError;
use runne_domain::event::Actor;
use runne_domain::task_run::{TaskRun, TaskRunState};

use crate::error::RuntimeError;
use crate::handle::RuntimeHandle;

mod legacy_submit;
mod successor;

/// Optional metadata adapter for one transactionally-read TaskRun effects snapshot.
/// Durable facts are read by the EventStore; this hook adds only selected adapter metadata.
pub trait TaskRunEffectsEnricher: Send + Sync + 'static {
    /// Reads and scans tool evidence through the daemon-owned key boundary.
    fn tool_activity(
        &self,
        _principal: &runne_api::ApiPrincipalId,
        _taskrun_id: runne_domain::id::TaskRunId,
    ) -> Result<runne_api::TaskRunToolActivityV1, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }

    /// Authenticates only the already-loaded sealed record within the EventStore read.
    fn remote_fact_authenticator(
        &self,
    ) -> Option<std::sync::Arc<dyn runne_application::provider::ProviderRemoteFactAuthenticator>>
    {
        None
    }

    /// Authenticates source1 encrypted journal terminals in the same effects read.
    fn unknown_terminal_fact_authenticator(
        &self,
    ) -> Option<
        std::sync::Arc<dyn runne_application::provider::ProviderUnknownTerminalFactAuthenticator>,
    > {
        None
    }

    /// Resolves the exact historic model pin used by the same read's successor validator.
    fn historical_model_resolver(
        &self,
    ) -> Option<std::sync::Arc<dyn runne_application::provider::HistoricalProviderModelResolver>>
    {
        None
    }

    /// Returns only runtime adapter capabilities and metadata-derived availability.
    /// Implementations must not read or mutate the effects store here.
    fn runtime_metadata(
        &self,
        _snapshot: &runne_application::ports::TaskRunEffectsReadSnapshot,
    ) -> Result<
        Option<(
            runne_api::RemoteEffectAvailabilityV1,
            runne_api::RemoteEffectCapabilitiesV1,
        )>,
        TaskRunHostError,
    > {
        Ok(None)
    }
}

include!("task_run_host/commands.rs");
include!("task_run_host/query.rs");
include!("task_run_host/helpers.rs");
