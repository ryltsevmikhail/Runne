use super::*;

impl DaemonAutomaticTaskRuns {
    pub(super) async fn execute_provider_candidate(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> Result<(), AutomaticTaskRunError> {
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
        let tool_profile =
            provider.accepts_tool_profile_selection(claimed.selected_profile.as_ref());
        #[cfg(not(all(feature = "desktop-protected", target_os = "linux")))]
        if tool_profile {
            self.release_before_effect(identity, claimed.stream_version)?;
            return Err(AutomaticTaskRunError::Unavailable);
        }
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
        let job = CanonicalProviderExecutionJob {
            context: generation_context.clone(),
            original: original.clone(),
            started: started.clone(),
        };
        #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
        let d2_round = if tool_profile {
            match self.commit_d2_plan_for_claim(&identity, &claimed) {
                Ok(round) => Some(round),
                Err(error) => {
                    // The claim and its conversation text are already admitted,
                    // but no provider delivery or tool effect exists and the
                    // automatic worker never rescans a claimed run: settle the
                    // closed failure instead of leaving the run `running`.
                    self.fail_claimed_d2_before_dispatch(&job, &identity);
                    return Err(error);
                }
            }
        } else {
            None
        };
        #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
        let d2_stop_job = job.clone();
        let provider_future = async {
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            if let Some(round) = d2_round {
                let selected = claimed
                    .selected_profile
                    .clone()
                    .ok_or(CanonicalProviderExecutionError::RejectedBeforeEffect)?;
                return self
                    .execute_d2_rounds(
                        provider.as_ref(),
                        job,
                        identity.clone(),
                        selected,
                        round,
                        claimed.workspace_id,
                    )
                    .await;
            }
            provider
                .execute_claimed_selected_profile(
                    job,
                    identity.clone(),
                    claimed.selected_profile.clone(),
                )
                .await
                .map(|_| ClaimedProviderOutcome::Text)
        };
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
            Ok(ClaimedProviderOutcome::Text) => Ok(()),
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            Ok(ClaimedProviderOutcome::ToolLoopCompleted) => Ok(()),
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            Ok(ClaimedProviderOutcome::ToolLoopFailed) if tool_profile => {
                #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
                if self
                    .settle_d2_tool_loop_cancellation(
                        &generation_context,
                        &original,
                        &started,
                        &identity,
                    )
                    .is_ok()
                {
                    return Ok(());
                }
                Err(AutomaticTaskRunError::Failed)
            }
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            Ok(ClaimedProviderOutcome::ToolLoopFailed) => Err(AutomaticTaskRunError::Failed),
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            Err(error) if tool_profile => {
                d2_stage(provider_error_stage(error));
                let reason = super::support::provider_failure_reason(error);
                #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
                if self
                    .settle_d2_tool_loop_cancellation(
                        &generation_context,
                        &original,
                        &started,
                        &identity,
                    )
                    .is_ok()
                {
                    return Ok(());
                }
                #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
                if let Ok(cycle_id) = self.current_cycle_id(identity.taskrun_id)
                    && self
                        .fail_d2_cycle(&d2_stop_job, &identity, cycle_id, reason)
                        .is_ok()
                {
                    return Err(AutomaticTaskRunError::Failed);
                }
                Err(AutomaticTaskRunError::Uncertain)
            }
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
}
