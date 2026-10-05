use super::*;
use runne_application::{commands::CompleteLoopCycleInput, ports::TaskRunProviderToolResultRef};
use runne_domain::agent_loop::LoopDisposition;

fn now_unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

impl DaemonAutomaticTaskRuns {
    pub(in crate::application::exec_taskrun_worker::provider) async fn execute_d2_rounds(
        &self,
        provider: &crate::canonical_provider::DaemonCanonicalProviderService,
        job: CanonicalProviderExecutionJob,
        assignment: TaskRunAssignmentIdentity,
        selected: runne_domain::task_run::SelectedProviderProfile,
        mut round: crate::canonical_provider::D2ProviderRound,
        workspace_id: runne_domain::id::WorkspaceId,
    ) -> Result<super::ClaimedProviderOutcome, CanonicalProviderExecutionError> {
        loop {
            d2_stage("provider_round_start");
            if round.round_index == 0 && self.preflight_d2_tool_helper(workspace_id).is_err() {
                let cycle_id = self
                    .current_cycle_id(assignment.taskrun_id)
                    .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
                self.fail_d2_cycle(
                    &job,
                    &assignment,
                    cycle_id,
                    runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
                )
                .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
                return Ok(super::ClaimedProviderOutcome::ToolLoopFailed);
            }
            let outcome = provider
                .execute_claimed_tool_round(
                    job.clone(),
                    assignment.clone(),
                    selected.clone(),
                    round.clone(),
                )
                .await
                .inspect_err(|error| {
                    d2_stage(provider_error_stage(*error));
                })?;
            match outcome {
                crate::canonical_provider::D2ProviderRoundOutcome::Proposal { call, sources } => {
                    d2_stage("proposal_received");
                    if round.round_index > 1 {
                        let cycle_id = round
                            .previous_tool_result
                            .as_ref()
                            .map(|previous| previous.cycle_id)
                            .or_else(|| self.current_cycle_id(assignment.taskrun_id).ok())
                            .ok_or(CanonicalProviderExecutionError::Uncertain)?;
                        self.fail_d2_cycle(
                            &job,
                            &assignment,
                            cycle_id,
                            runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
                        )
                        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
                        return Ok(super::ClaimedProviderOutcome::ToolLoopFailed);
                    }
                    let principal =
                        runne_api::ApiPrincipalId::new(job.context.principal_id.0.clone())
                            .map_err(|_| CanonicalProviderExecutionError::PolicyDenied)?;
                    let current = self
                        .store
                        .load_task_run(assignment.taskrun_id)
                        .map_err(|_| CanonicalProviderExecutionError::Unavailable)?;
                    if current.current_version != round.current_taskrun_head {
                        return Err(CanonicalProviderExecutionError::Conflict);
                    }
                    d2_stage("proposal_persist_start");
                    let cycle_id = match round.previous_tool_result.as_ref() {
                        Some(previous) => previous.cycle_id,
                        None => self
                            .current_cycle_id(assignment.taskrun_id)
                            .map_err(|_| CanonicalProviderExecutionError::Uncertain)?,
                    };
                    if self
                        .persist_tool_proposal(
                            &job.context,
                            &assignment,
                            round.round_index,
                            current.current_version,
                            call,
                            sources,
                            workspace_id,
                            principal,
                        )
                        .await
                        .is_err()
                    {
                        // The provider returned a complete, authenticated tool
                        // proposal, but the local authority rejected or could
                        // not materialize it.  No helper can run without the
                        // durable invocation row; settle the local cycle while
                        // preserving the provider journal as its own evidence.
                        self.fail_d2_cycle(
                            &job,
                            &assignment,
                            cycle_id,
                            runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
                        )
                        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
                        return Ok(super::ClaimedProviderOutcome::ToolLoopFailed);
                    }
                    d2_stage("proposal_persisted");
                    let key = runne_store::store::taskrun_tool_invocation::ToolInvocationKey {
                        taskrun_id: assignment.taskrun_id,
                        attempt_id: assignment.attempt_id,
                        cycle_id,
                        proposal_index: round.round_index,
                    };
                    let stored = self
                        .store
                        .load_taskrun_tool_invocation(key)
                        .map_err(|_| CanonicalProviderExecutionError::Unavailable)?;
                    let Some(result) = stored.as_ref().and_then(|record| {
                        (record.receipt.state == runne_store::store::taskrun_tool_invocation::ToolInvocationState::Result
                            && record.local_stop_state == runne_store::store::taskrun_tool_invocation::LocalToolStopState::ProvedEmpty
                            && record.managed_area_identity == record.empty_proof_identity)
                            .then_some(record.receipt.result.clone())
                            .flatten()
                    }) else {
                        let known_rejection = stored.as_ref().is_some_and(|record| {
                            record.receipt.state
                                == runne_store::store::taskrun_tool_invocation::ToolInvocationState::Denied
                                || (record.receipt.state
                                    == runne_store::store::taskrun_tool_invocation::ToolInvocationState::Proposed
                                    && now_unix_millis() >= record.binding.approval_expires_at)
                        });
                        if !known_rejection {
                            return Err(CanonicalProviderExecutionError::Uncertain);
                        }
                        self.fail_d2_cycle(
                            &job,
                            &assignment,
                            key.cycle_id,
                            runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
                        )
                            .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
                        return Ok(super::ClaimedProviderOutcome::ToolLoopFailed);
                    };
                    let previous = TaskRunProviderToolResultRef {
                        attempt_id: assignment.attempt_id,
                        cycle_id: key.cycle_id,
                        proposal_index: key.proposal_index,
                        semantic_digest: self
                            .store
                            .load_taskrun_tool_invocation(key)
                            .map_err(|_| CanonicalProviderExecutionError::Unavailable)?
                            .ok_or(CanonicalProviderExecutionError::Unavailable)?
                            .binding
                            .semantic_digest,
                        result_digest: result.digest,
                    };
                    d2_stage("continuation_target_check");
                    let continuation_target_fence = self
                        .d2_current_target_fence(
                            workspace_id,
                            assignment.taskrun_id,
                            round.round_index as usize + 1,
                        )
                        .and_then(|fence| fence.validate().map(|()| fence))
                        .map_err(|_| {
                            d2_stage("continuation_target_stale");
                            CanonicalProviderExecutionError::Conflict
                        })?;
                    d2_stage("continuation_target_valid");
                    let head = self
                        .store
                        .load_task_run(assignment.taskrun_id)
                        .map_err(|_| CanonicalProviderExecutionError::Unavailable)?
                        .current_version;
                    round = crate::canonical_provider::D2ProviderRound {
                        current_taskrun_head: head,
                        round_index: round.round_index + 1,
                        previous_tool_result: Some(previous),
                        continuation_target_fence: Some(continuation_target_fence),
                    };
                }
                crate::canonical_provider::D2ProviderRoundOutcome::FinalStop {
                    terminal,
                    sources,
                } => {
                    d2_stage("final_stop_received");
                    if round.round_index != 2 || round.previous_tool_result.is_none() {
                        let cycle_id = round
                            .previous_tool_result
                            .as_ref()
                            .map(|previous| previous.cycle_id)
                            .or_else(|| self.current_cycle_id(assignment.taskrun_id).ok())
                            .ok_or(CanonicalProviderExecutionError::Uncertain)?;
                        self.fail_d2_cycle(
                            &job,
                            &assignment,
                            cycle_id,
                            runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
                        )
                        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
                        return Ok(super::ClaimedProviderOutcome::ToolLoopFailed);
                    }
                    d2_stage("final_text_start");
                    let final_text = provider
                        .recover_d2_final_text(&job, &terminal)
                        .inspect_err(|_error| {
                            d2_stage("final_text_error");
                        })?;
                    d2_stage("final_text_recovered");
                    d2_stage("current_targets_start");
                    self.validate_d2_current_targets(workspace_id, assignment.taskrun_id)
                        .map_err(|_| {
                            d2_stage("current_targets_error");
                            CanonicalProviderExecutionError::Uncertain
                        })?;
                    d2_stage("current_targets_valid");
                    d2_stage("evaluation_start");
                    let evaluation =
                        crate::application::tool_authorities::derive_expected_evaluation(
                            self.store.clone(),
                            self.provider.clone(),
                            self.root_admission.clone(),
                            assignment.taskrun_id,
                        )
                        .map_err(|_| {
                            d2_stage("evaluation_error");
                            CanonicalProviderExecutionError::Uncertain
                        })?;
                    d2_stage("evaluation_ready");
                    let cycle_id = self
                        .current_cycle_id(assignment.taskrun_id)
                        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
                    let head = self
                        .store
                        .load_task_run(assignment.taskrun_id)
                        .map_err(|_| CanonicalProviderExecutionError::Unavailable)?
                        .current_version;
                    let loop_service = self
                        .tool_loop_service
                        .as_ref()
                        .ok_or(CanonicalProviderExecutionError::Unavailable)?;
                    d2_stage("complete_cycle_start");
                    loop_service
                        .complete_loop_cycle(
                            &Self::d2_command_context(
                                job.context.principal_id.clone(),
                                job.context.actor.clone(),
                                assignment.taskrun_id,
                                assignment.attempt_id,
                                Some(cycle_id),
                                "complete-cycle",
                                None,
                            ),
                            CompleteLoopCycleInput {
                                taskrun_id: assignment.taskrun_id,
                                expected_version: head,
                                cycle_id,
                                disposition: LoopDisposition::Complete {
                                    plan_evaluation_ref: evaluation.reference.clone(),
                                },
                            },
                        )
                        .map_err(|_| {
                            d2_stage("complete_cycle_error");
                            CanonicalProviderExecutionError::Uncertain
                        })?;
                    d2_stage("cycle_completed");
                    let started = job.started.clone();
                    d2_stage("conversation_projection_start");
                    let _receipt = crate::application::tool_loop_completion::complete_d2_tool_loop(
                        &self.store,
                        &job.context,
                        &job.original,
                        &started,
                        &assignment,
                        cycle_id,
                        evaluation.reference,
                        &terminal,
                        &sources,
                        final_text,
                    )
                    .map_err(|_| {
                        d2_stage("conversation_projection_error");
                        CanonicalProviderExecutionError::Uncertain
                    })?;
                    d2_stage("conversation_projected");
                    return Ok(super::ClaimedProviderOutcome::ToolLoopCompleted);
                }
            }
        }
    }
}
