use super::logging::warn_lease_renewal_failure;
use super::*;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, ConversationTextCompletion,
    FinishConversationTextInput,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, EventStore, TaskRunAssignmentIdentity,
    TaskRunAssignmentPort, TaskRunExecutionInputPort, TaskRunLeaseRenewal, TaskRunQueueCandidate,
    TextGenerationReceipt,
};
use runne_domain::id::CommandId;
use runne_domain::message::MessageText;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_runtime::canonical_provider_execution::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
};
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunError;
use std::sync::atomic::Ordering;

impl DaemonAutomaticTaskRuns {
    pub(in crate::application) async fn execute_one(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> Result<(), AutomaticTaskRunError> {
        if local_command_route(
            self.is_local_command_candidate(candidate)?,
            cfg!(all(feature = "desktop-protected", target_os = "linux")),
        )? {
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            return self
                .execute_local_candidate(candidate)
                .await
                .unwrap_or(Err(AutomaticTaskRunError::Uncertain));
            #[cfg(not(all(feature = "desktop-protected", target_os = "linux")))]
            return Err(AutomaticTaskRunError::Unavailable);
        }
        let (requested_model, selected_profile) = self.submit_selection_before_claim(candidate)?;
        let Some(provider) = &self.provider else {
            return Err(AutomaticTaskRunError::Unavailable);
        };
        if !provider.accepts_profile_selection(selected_profile.as_ref()) {
            return Err(AutomaticTaskRunError::RejectedBeforeEffect);
        }
        let model_matches = provider
            .accepts_model_for_profile(selected_profile.as_ref(), requested_model.as_deref());
        let context = Self::runtime_context();
        let node_epoch = self.current_epoch.load(Ordering::Acquire);
        let claim = self
            .taskruns
            .claim_task_run(
                &context,
                runne_application::service::ClaimTaskRunInput {
                    taskrun_id: candidate.taskrun_id,
                    expected_version: candidate.current_version,
                    node_id: self.node_id.clone(),
                    node_epoch,
                    capability_descriptor: "linux-executor-v1".into(),
                    lease_duration_ms: 300_000,
                },
                &self.store,
            )
            .map_err(|_| AutomaticTaskRunError::Unavailable)?;
        let receipt = match claim {
            runne_application::ports::TaskRunClaimResult::Committed(receipt)
            | runne_application::ports::TaskRunClaimResult::Duplicate(receipt) => receipt,
        };
        let identity = TaskRunAssignmentIdentity {
            taskrun_id: receipt.taskrun_id,
            attempt_id: receipt.attempt_id,
            node_id: receipt.node_id.clone(),
            node_epoch: receipt.node_epoch,
            fence: receipt.fence,
        };
        let claimed = match self
            .store
            .read_taskrun_execution_input(identity.clone(), receipt.new_version)
        {
            Ok(input) => input,
            Err(_) => {
                self.release_before_effect(identity, receipt.new_version)?;
                return Err(AutomaticTaskRunError::Failed);
            }
        };
        if !model_matches
            || requested_model.as_deref() != claimed.requested_model.as_deref()
            || selected_profile != claimed.selected_profile
        {
            self.release_before_effect(identity, claimed.stream_version)?;
            return Err(AutomaticTaskRunError::Failed);
        }
        if !provider.accepts_profile_selection(claimed.selected_profile.as_ref()) {
            self.release_before_effect(identity, claimed.stream_version)?;
            return Err(AutomaticTaskRunError::Failed);
        }
        if !provider.accepts_model_for_profile(
            claimed.selected_profile.as_ref(),
            claimed.requested_model.as_deref(),
        ) {
            self.release_before_effect(identity, claimed.stream_version)?;
            return Err(AutomaticTaskRunError::Failed);
        }
        let conversation = match self.store.load_conversation(claimed.conversation_id) {
            Ok(conversation) => conversation,
            Err(_) => {
                self.release_before_effect(identity, claimed.stream_version)?;
                return Err(AutomaticTaskRunError::Unavailable);
            }
        };
        let original = BeginConversationTextInput {
            conversation_id: claimed.conversation_id,
            expected_version: conversation.current_version,
            text: match MessageText::new(claimed.input.prompt().to_owned()) {
                Ok(text) => text,
                Err(_) => {
                    self.release_before_effect(identity, claimed.stream_version)?;
                    return Err(AutomaticTaskRunError::RejectedBeforeEffect);
                }
            },
        };
        let generation_context =
            Self::command_context(claimed.principal_id.clone(), claimed.submit_actor.clone());
        let started = match self.text.begin_claimed_text(
            &generation_context,
            BeginClaimedConversationTextInput {
                original: original.clone(),
                taskrun_id: claimed.taskrun_id,
                attempt_id: claimed.attempt_id,
                taskrun_version: claimed.stream_version,
                workspace_id: claimed.workspace_id,
                assignment: identity.clone(),
            },
        ) {
            Ok(receipt) => receipt,
            Err(error) if begin_failure_proves_no_start(&error) => {
                self.release_before_effect(identity, claimed.stream_version)?;
                return Err(AutomaticTaskRunError::RejectedBeforeEffect);
            }
            Err(_) => return Err(AutomaticTaskRunError::Uncertain),
        };
        let provider_future = provider.execute_claimed_selected_profile(
            CanonicalProviderExecutionJob {
                context: generation_context.clone(),
                original: original.clone(),
                started: started.clone(),
            },
            identity.clone(),
            claimed.selected_profile.clone(),
        );
        tokio::pin!(provider_future);
        let mut renewals = tokio::time::interval(std::time::Duration::from_secs(30));
        let outcome = loop {
            tokio::select! {
                result = &mut provider_future => break result,
                _ = renewals.tick() => {
                    let renewal = TaskRunLeaseRenewal {
                        identity: identity.clone(),
                        renewal_id: CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
                        lease_duration_ms: 300_000,
                    };
                    if self.store.renew_taskrun_assignment_lease(renewal).is_err() {
                        warn_lease_renewal_failure(identity.taskrun_id);
                    }
                }
            }
        };
        match outcome {
            Ok(_) => Ok(()),
            Err(
                CanonicalProviderExecutionError::RejectedBeforeEffect
                | CanonicalProviderExecutionError::PolicyDenied,
            ) => {
                self.finish_failure(
                    &generation_context,
                    &original,
                    &started,
                    runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
                )
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
                Err(AutomaticTaskRunError::RejectedBeforeEffect)
            }
            Err(
                CanonicalProviderExecutionError::RemoteFailed
                | CanonicalProviderExecutionError::RemoteIncomplete,
            ) => {
                self.finish_failure(
                    &generation_context,
                    &original,
                    &started,
                    runne_domain::conversation::GenerationFailureReason::ProviderExecutionFailed,
                )
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
                Err(AutomaticTaskRunError::Failed)
            }
            Err(_) => Err(AutomaticTaskRunError::Uncertain),
        }
    }

    fn is_local_command_candidate(
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
    fn finish_failure(
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
fn begin_failure_proves_no_start(
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

fn local_command_route(
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
