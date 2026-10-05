use super::*;
use runne_application::commands::BeginConversationTextInput;
use runne_application::ports::LoadedStream;

mod projection;

impl DaemonAutomaticTaskRuns {
    pub(super) fn stop_d2_after_restart(
        &self,
        candidate: runne_store::store::D2FailureRecoveryCandidate,
        taskrun: LoadedStream,
        aggregate: TaskRun,
    ) -> Result<bool, &'static str> {
        use runne_application::commands::CompleteLoopCycleInput;
        use runne_domain::agent_loop::LoopDisposition;
        let snapshot = aggregate.snapshot_v1();
        let is_d2 = snapshot
            .input()
            .and_then(|input| input.selected_profile())
            .is_some_and(|profile| profile.profile_id() == "runne-linux-agent-tools-v1");
        if !is_d2 {
            return Ok(false);
        }
        let budget = self
            .store
            .load_taskrun_tool_loop_budget_ref(candidate.taskrun_id)
            .map_err(|_| "restart_budget_read")?;
        if budget
            .as_ref()
            .is_some_and(|budget| budget.attempt_id != candidate.attempt_id)
        {
            return Err("restart_budget_attempt");
        }
        let early_cycle = snapshot.active_cycle().is_some_and(|cycle| {
            matches!(
                cycle.state,
                runne_domain::agent_loop::LoopCycleState::Observing
                    | runne_domain::agent_loop::LoopCycleState::Proposing
            ) && cycle.plan_revision_ref.is_none()
                && cycle.expected_proposal_indexes.is_empty()
                && cycle.recorded_outcomes.is_empty()
        });
        if snapshot.active_cycle().is_none() || early_cycle {
            return self.stop_d2_before_cycle(candidate, taskrun);
        }
        let cycle = snapshot.active_cycle().ok_or("restart_cycle_missing")?;
        let records = self
            .store
            .load_taskrun_tool_invocations_for_taskrun(candidate.taskrun_id)
            .map_err(|_| "restart_invocations_read")?;
        let mut known_results = 0usize;
        let mut stopped_unknown = 0usize;
        let mut unlaunched = 0usize;
        for record in records
            .iter()
            .filter(|record| record.binding.key.attempt_id == candidate.attempt_id)
        {
            let stopped = record.local_stop_state
                == runne_store::store::taskrun_tool_invocation::LocalToolStopState::ProvedEmpty
                && record.managed_area_identity == record.empty_proof_identity
                && record.binding.key.cycle_id == cycle.cycle_id;
            match record.receipt.state {
                runne_store::store::taskrun_tool_invocation::ToolInvocationState::Result => {
                    let Some(result) = record.receipt.result.as_ref() else {
                        return Err("restart_result_missing");
                    };
                    if !stopped || result.truncated {
                        return Ok(false);
                    }
                    known_results += 1;
                }
                runne_store::store::taskrun_tool_invocation::ToolInvocationState::Uncertain
                | runne_store::store::taskrun_tool_invocation::ToolInvocationState::AuditOnly => {
                    if !stopped {
                        return Ok(false);
                    }
                    stopped_unknown += 1;
                }
                runne_store::store::taskrun_tool_invocation::ToolInvocationState::Proposed
                | runne_store::store::taskrun_tool_invocation::ToolInvocationState::Approved
                | runne_store::store::taskrun_tool_invocation::ToolInvocationState::Denied => {
                    if record.release_started
                        || record.local_stop_state != runne_store::store::taskrun_tool_invocation::LocalToolStopState::NotLaunched
                        || record.managed_area_identity.is_some() { return Ok(false); }
                    unlaunched += 1;
                }
                runne_store::store::taskrun_tool_invocation::ToolInvocationState::Claimed => {
                    if record.claim_assignment.as_ref() != Some(&candidate.assignment)
                        || record.release_started
                        || record.local_stop_state
                            != runne_store::store::taskrun_tool_invocation::LocalToolStopState::NotLaunched
                        || record.managed_area_identity.is_some()
                        || record.empty_proof_identity.is_some()
                        || record.receipt.result.is_some()
                    {
                        return Ok(false);
                    }
                    unlaunched += 1;
                }
                _ => return Ok(false),
            }
        }
        if budget.is_none()
            && records
                .iter()
                .any(|record| record.binding.key.attempt_id == candidate.attempt_id)
        {
            return Err("restart_budget_missing_with_invocations");
        }
        self.store
            .authorize_d2_failure_recovery(
                candidate.taskrun_id,
                &candidate.assignment,
                taskrun.current_version,
                self.epoch,
            )
            .map_err(|_| "restart_authority")?;
        let unresolved = cycle
            .expected_proposal_indexes
            .iter()
            .copied()
            .filter(|index| {
                !cycle
                    .recorded_outcomes
                    .iter()
                    .any(|outcome| outcome.proposal_index == *index)
            })
            .collect();
        let service = self
            .tool_loop_service
            .as_ref()
            .ok_or("restart_loop_service")?;
        let recovery_context = Self::d2_command_context(
            runne_application::ports::PrincipalId(
                candidate.principal_id.clone().ok_or("restart_principal")?,
            ),
            runne_domain::event::Actor::new("runne-runtime").map_err(|_| "restart_actor")?,
            candidate.taskrun_id,
            candidate.attempt_id,
            Some(cycle.cycle_id),
            "interrupted-by-restart",
            None,
        );
        let (loop_reason, projection_reason) =
            if stopped_unknown > 0 || (known_results == 0 && unlaunched > 0) {
                (
                    "D2 tool approval or effect did not complete safely",
                    runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
                )
            } else {
                (
                    "interrupted_by_restart",
                    runne_domain::conversation::GenerationFailureReason::InterruptedByRestart,
                )
            };
        self.store
            .verify_d2_tool_loop_safe_stop(
                candidate.taskrun_id,
                candidate.attempt_id,
                cycle.cycle_id,
                &candidate.assignment,
                taskrun.current_version,
                known_results > 0,
            )
            .map_err(|_| "restart_safe_stop")?;
        service
            .complete_loop_cycle(
                &recovery_context,
                CompleteLoopCycleInput {
                    taskrun_id: candidate.taskrun_id,
                    expected_version: taskrun.current_version,
                    cycle_id: cycle.cycle_id,
                    disposition: LoopDisposition::Fail {
                        reason: loop_reason.into(),
                        unresolved_proposals: unresolved,
                    },
                },
            )
            .map_err(|_| "restart_cycle_failure")?;
        self.project_d2_interrupted(candidate, cycle.cycle_id, projection_reason)?;
        Ok(true)
    }

    fn stop_d2_before_cycle(
        &self,
        candidate: runne_store::store::D2FailureRecoveryCandidate,
        taskrun: LoadedStream,
    ) -> Result<bool, &'static str> {
        self.store
            .authorize_d2_failure_recovery(
                candidate.taskrun_id,
                &candidate.assignment,
                taskrun.current_version,
                self.epoch,
            )
            .map_err(|_| "restart_authority")?;
        let (Some(conversation_id), Some(principal_id)) =
            (candidate.conversation_id, candidate.principal_id.clone())
        else {
            return Err("restart_origin_missing");
        };
        let conversation = self
            .store
            .load_conversation(conversation_id)
            .map_err(|_| "restart_conversation")?;
        let mut messages = conversation.events.iter().filter(|event| {
            matches!(event.payload(), ConversationEvent::UserMessageAppended { taskrun_id, attempt_id, .. }
                if *taskrun_id == candidate.taskrun_id && *attempt_id == candidate.attempt_id)
        });
        let event = messages.next().ok_or("restart_message_missing")?;
        if messages.next().is_some() {
            return Err("restart_message_duplicate");
        }
        let ConversationEvent::UserMessageAppended {
            message_id, text, ..
        } = event.payload()
        else {
            return Err("restart_message_invalid");
        };
        let command_id = *event.command_id();
        let idempotency_key = event.idempotency_key().clone();
        let started = self
            .store
            .load_text_generation_receipt_by_command(command_id, &idempotency_key)
            .map_err(|_| "restart_started_receipt")?;
        if started.phase != TextGenerationPhase::Started
            || started.taskrun_id != candidate.taskrun_id
            || started.attempt_id != candidate.attempt_id
            || started.conversation_id != conversation_id
            || started.user_message_id != *message_id
            || started.conversation_version != event.sequence()
        {
            return Err("restart_started_mismatch");
        }
        let original = BeginConversationTextInput {
            conversation_id,
            expected_version: event.sequence().checked_sub(1).ok_or("restart_version")?,
            text: MessageText::new(text.as_str().to_owned()).map_err(|_| "restart_text")?,
        };
        let context = ApplicationCommandContext {
            command_id,
            idempotency_key,
            principal_id: runne_application::ports::PrincipalId(principal_id),
            actor: event.actor().clone(),
        };
        self.text
            .finish_text(
                &context,
                runne_application::commands::FinishConversationTextInput {
                    original,
                    started,
                    completion:
                        runne_application::commands::ConversationTextCompletion::D2ToolLoopRestart {
                            evidence: runne_application::ports::D2ToolLoopRestartEvidence {
                                assignment: candidate.assignment,
                                recovery_epoch: self.epoch,
                                expected_taskrun_head: taskrun.current_version,
                            },
                        },
                },
            )
            .map_err(|error| {
                use runne_application::conversation_text_service::ConversationTextServiceError as E;
                let stage = match error {
                    E::ReceiptMismatch => "restart_finish_receipt_mismatch",
                    E::Commit(_) => "restart_finish_commit",
                    E::Conflict => "restart_finish_conflict",
                    E::StoredDataUnavailable => "restart_finish_data_unavailable",
                    _ => "restart_finish_other",
                };
                crate::application::tool_loop_plan::worker::diagnostics::d2_test_stage(stage);
                "restart_pre_cycle_projection"
            })?;
        Ok(true)
    }
}
