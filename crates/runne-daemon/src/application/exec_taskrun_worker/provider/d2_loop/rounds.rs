use super::*;
#[path = "completion.rs"]
mod completion;
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
        let mut proposal_index = round
            .previous_tool_result
            .map_or(0, |p| p.proposal_index + 1);
        let mut pending = std::collections::VecDeque::new();
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
            let outcome = if let Some((call, sources)) = pending.pop_front() {
                crate::canonical_provider::D2ProviderRoundOutcome::Proposal { call, sources }
            } else {
                provider
                    .execute_claimed_tool_round(
                        job.clone(),
                        assignment.clone(),
                        selected.clone(),
                        round.clone(),
                    )
                    .await
                    .inspect_err(|error| {
                        d2_stage(provider_error_stage(*error));
                    })?
            };
            match outcome {
                crate::canonical_provider::D2ProviderRoundOutcome::Batch { proposals } => {
                    if !provider.coding_agent_tools_enabled()
                        || !pending.is_empty()
                        || proposals.is_empty()
                        || proposals.len() > 16
                        || proposal_index as usize + proposals.len() > 32
                    {
                        return Err(CanonicalProviderExecutionError::RejectedBeforeEffect);
                    }
                    pending.extend(proposals);
                }
                crate::canonical_provider::D2ProviderRoundOutcome::Proposal { call, sources } => {
                    d2_stage("proposal_received");
                    if proposal_index
                        >= if provider.coding_agent_tools_enabled() {
                            32
                        } else {
                            2
                        }
                    {
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
                    let mut current = self
                        .store
                        .load_task_run(assignment.taskrun_id)
                        .map_err(|_| CanonicalProviderExecutionError::Unavailable)?;
                    if current.current_version != round.current_taskrun_head {
                        return Err(CanonicalProviderExecutionError::Conflict);
                    }
                    if provider.coding_agent_tools_enabled() {
                        use sha2::Digest;
                        let args: serde_json::Value = serde_json::from_str(&call.arguments_json)
                            .map_err(|_| CanonicalProviderExecutionError::RejectedBeforeEffect)?;
                        let bytes=serde_json::to_vec(&serde_json::json!({"call_id":call.call_id,"tool_name":call.tool_name,"arguments":args}))
                            .map_err(|_|CanonicalProviderExecutionError::RejectedBeforeEffect)?;
                        current.current_version = self
                            .extend_coding_plan(
                                &job.context,
                                &assignment,
                                current.current_version,
                                proposal_index,
                                runne_domain::id::IntegrityDigest::from_bytes(
                                    sha2::Sha256::digest(bytes).into(),
                                ),
                            )
                            .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
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
                            proposal_index,
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
                        proposal_index,
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
                            proposal_index as usize + 1,
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
                        round_index: round.round_index + u32::from(pending.is_empty()),
                        previous_tool_result: Some(previous),
                        continuation_target_fence: Some(continuation_target_fence),
                    };
                    proposal_index += 1;
                }
                crate::canonical_provider::D2ProviderRoundOutcome::FinalStop {
                    terminal,
                    sources,
                } => {
                    return self.complete_d2_stop(
                        provider,
                        job,
                        assignment,
                        round,
                        workspace_id,
                        terminal,
                        sources,
                    );
                }
            }
        }
    }
}
