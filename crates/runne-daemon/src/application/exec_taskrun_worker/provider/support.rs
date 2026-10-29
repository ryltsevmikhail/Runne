use super::*;

impl DaemonAutomaticTaskRuns {
    pub(super) fn is_local_command_candidate(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> Result<bool, AutomaticTaskRunError> {
        let stream = self
            .store
            .load_task_run(candidate.taskrun_id)
            .map_err(|_| AutomaticTaskRunError::Unavailable)?;
        if stream.current_version != candidate.current_version {
            return Err(AutomaticTaskRunError::Uncertain);
        }
        let task = TaskRun::replay(&stream.events).map_err(|_| AutomaticTaskRunError::Uncertain)?;
        if task.state() != TaskRunState::Queued {
            return Err(AutomaticTaskRunError::Uncertain);
        }
        Ok(task
            .snapshot_v1()
            .input()
            .and_then(|input| input.local_command())
            .is_some())
    }

    pub(super) fn finish_failure(
        &self,
        context: &ApplicationCommandContext,
        original: &BeginConversationTextInput,
        started: &TextGenerationReceipt,
        reason: runne_domain::conversation::GenerationFailureReason,
    ) -> Result<(), AutomaticTaskRunError> {
        self.text
            .finish_text(
                context,
                FinishConversationTextInput {
                    original: original.clone(),
                    started: started.clone(),
                    completion: ConversationTextCompletion::Rejected { reason },
                },
            )
            .map(|_| ())
            .map_err(|_| AutomaticTaskRunError::Uncertain)
    }
}

pub(super) enum ClaimedProviderOutcome {
    Text,
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    ToolLoopCompleted,
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    ToolLoopFailed,
}

pub(super) fn begin_failure_proves_no_start(
    error: &runne_application::conversation_text_service::ConversationTextServiceError,
) -> bool {
    use runne_application::conversation_text_service::ConversationTextServiceError as Error;
    matches!(
        error,
        Error::WriterFenced
            | Error::ProhibitedSecretMaterial
            | Error::ConversationNotFound
            | Error::Conflict
            | Error::ConversationDomain(_)
            | Error::TaskRunDomain
            | Error::IdGeneration(_)
            | Error::MaterializationFailed
            | Error::ReceiptMismatch
    )
}

/// Closed terminal reason for a coding round that ended in an error.
///
/// Only an error that happened before any external effect is reported as a
/// rejection; every other provider error is a failure, never a claim that no
/// delivery was attempted.
pub(super) const fn provider_failure_reason(
    error: CanonicalProviderExecutionError,
) -> runne_domain::conversation::GenerationFailureReason {
    use runne_domain::conversation::GenerationFailureReason as Reason;
    match error {
        CanonicalProviderExecutionError::RejectedBeforeEffect
        | CanonicalProviderExecutionError::PolicyDenied => Reason::ProviderExecutionRejected,
        CanonicalProviderExecutionError::RemoteFailed
        | CanonicalProviderExecutionError::RemoteIncomplete
        | CanonicalProviderExecutionError::Uncertain
        | CanonicalProviderExecutionError::Unavailable
        | CanonicalProviderExecutionError::Conflict => Reason::ProviderExecutionFailed,
    }
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(super) fn provider_error_stage(error: CanonicalProviderExecutionError) -> &'static str {
    match error {
        CanonicalProviderExecutionError::RejectedBeforeEffect => "provider_rejected",
        CanonicalProviderExecutionError::RemoteFailed => "provider_remote_failed",
        CanonicalProviderExecutionError::RemoteIncomplete => "provider_remote_incomplete",
        CanonicalProviderExecutionError::Uncertain => "provider_uncertain",
        CanonicalProviderExecutionError::PolicyDenied => "provider_policy_denied",
        CanonicalProviderExecutionError::Unavailable => "provider_unavailable",
        CanonicalProviderExecutionError::Conflict => "provider_conflict",
    }
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[path = "stage_diagnostics.rs"]
mod stage_diagnostics;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(crate) use stage_diagnostics::d2_stage;

pub(super) fn local_command_route(
    is_local_command: bool,
    local_worker_available: bool,
) -> Result<bool, AutomaticTaskRunError> {
    if is_local_command && !local_worker_available {
        return Err(AutomaticTaskRunError::Unavailable);
    }
    Ok(is_local_command)
}

#[cfg(test)]
mod route_tests {
    use super::{AutomaticTaskRunError, local_command_route};

    #[test]
    fn typed_local_command_never_falls_back_to_provider_on_unsupported_target() {
        assert_eq!(
            local_command_route(true, false),
            Err(AutomaticTaskRunError::Unavailable)
        );
        assert_eq!(local_command_route(false, false), Ok(false));
    }
}
