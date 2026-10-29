use super::*;
use runne_application::ports::{
    EventStore, GateEvaluationRef, PlanEvaluation, VerificationQueryError, VerificationQueryPort,
};
use runne_domain::{
    agent_loop::{LoopCycleState, StepOutcomeType},
    task_run::{TaskRun, TaskRunState},
    verification::{PlanEvaluationRef, PlanEvaluationResult},
};
#[path = "verification/assemble.rs"]
mod assemble;
#[path = "verification/historical.rs"]
mod historical;
#[path = "verification/identity.rs"]
mod identity;
use identity::{deterministic_evaluation_id, hash};
impl VerificationQueryPort for D2ToolLoopAuthority {
    fn get_exact(
        &self,
        requested: &PlanEvaluationRef,
    ) -> Result<PlanEvaluation, VerificationQueryError> {
        self.evaluate_current(requested.taskrun_id, Some(requested))
    }
}

impl D2ToolLoopAuthority {
    pub(super) fn derive_expected_evaluation(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
    ) -> Result<PlanEvaluation, VerificationQueryError> {
        self.evaluate_current(taskrun_id, None)
    }

    pub(super) fn verify_historical_completed(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
    ) -> Result<PlanEvaluation, VerificationQueryError> {
        historical::verify(self, taskrun_id)
    }

    fn evaluate_current(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
        requested: Option<&PlanEvaluationRef>,
    ) -> Result<PlanEvaluation, VerificationQueryError> {
        let stream = self
            .store
            .load_task_run(taskrun_id)
            .map_err(|_| VerificationQueryError::Unavailable)?;
        self.evaluate_stream(taskrun_id, stream, requested, false)
    }

    fn evaluate_stream(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
        stream: runne_application::ports::LoadedStream,
        requested: Option<&PlanEvaluationRef>,
        historical: bool,
    ) -> Result<PlanEvaluation, VerificationQueryError> {
        if requested
            .is_some_and(|requested| stream.current_version != requested.evaluated_stream_head)
        {
            return Err(VerificationQueryError::Stale);
        }
        let task =
            TaskRun::replay(&stream.events).map_err(|_| VerificationQueryError::InvalidBinding)?;
        #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
        let workspace_id = stream
            .events
            .iter()
            .find_map(|event| match event.payload() {
                runne_domain::task_run::TaskRunEvent::TaskRunSubmitted { workspace_id, .. } => {
                    Some(*workspace_id)
                }
                _ => None,
            })
            .ok_or(VerificationQueryError::InvalidBinding)?;
        let snapshot = task.snapshot_v1();
        if snapshot.state() != TaskRunState::Running {
            return Err(VerificationQueryError::Stale);
        }
        let cycle = snapshot
            .active_cycle()
            .ok_or(VerificationQueryError::InvalidBinding)?;
        if cycle.state != LoopCycleState::Evaluating {
            return Err(VerificationQueryError::Stale);
        }
        let plan = cycle
            .plan_revision_ref
            .as_ref()
            .ok_or(VerificationQueryError::InvalidBinding)?;
        if plan.taskrun_id != taskrun_id
            || requested.is_some_and(|requested| {
                plan.plan_id != requested.plan_id || plan.revision != requested.plan_revision
            })
        {
            return Err(VerificationQueryError::InvalidBinding);
        }
        let records = self
            .store
            .load_taskrun_tool_invocations_for_taskrun(taskrun_id)
            .map_err(|_| VerificationQueryError::Unavailable)?;
        let coding = self
            .provider
            .as_ref()
            .is_some_and(|p| p.coding_agent_tools_enabled());
        if (if coding {
            records.len() > 32
        } else {
            records.len() != 2
        }) || cycle.recorded_outcomes.len() != records.len()
            || cycle
                .recorded_outcomes
                .iter()
                .any(|outcome| outcome.outcome_type != StepOutcomeType::Succeeded)
        {
            return Err(VerificationQueryError::InvalidBinding);
        }
        let mut current = records.iter().collect::<Vec<_>>();
        current.sort_by_key(|record| record.binding.key.proposal_index);
        if current
            .iter()
            .any(|record| record.binding.key.cycle_id != cycle.cycle_id)
            || cycle.expected_proposal_indexes != (0..current.len() as u32).collect::<Vec<_>>()
        {
            return Err(VerificationQueryError::InvalidBinding);
        }
        let mut saw_read = false;
        let mut saw_create = false;
        let mut evidence = Vec::with_capacity(current.len() * 96);
        let mut evaluated_at_unix_us = if coding {
            stream
                .events
                .last()
                .map_or(0, |e| e.timestamp().as_unix_micros())
        } else {
            0_i64
        };
        let plan_commit_position = stream.events.iter().position(|event| {
            matches!(event.payload(), runne_domain::task_run::TaskRunEvent::PlanCommitted { cycle_id, .. } if *cycle_id == cycle.cycle_id)
        }).ok_or(VerificationQueryError::InvalidBinding)? as u64 + 1;
        let (latest, last_command) = assemble::latest_targets(&current);
        for record in current {
            let binding = &record.binding;
            let result = record
                .receipt
                .result
                .as_ref()
                .ok_or(VerificationQueryError::InvalidBinding)?;
            if binding.key.attempt_id != cycle.attempt_id
                || record.local_stop_state
                    != runne_store::store::taskrun_tool_invocation::LocalToolStopState::ProvedEmpty
                || record.managed_area_identity != record.empty_proof_identity
                || record.managed_area_identity.as_ref().is_none_or(|area| {
                    area[84..100] != binding.key.managed_area_nonce(binding.semantic_digest)
                })
                || record.receipt.state
                    != runne_store::store::taskrun_tool_invocation::ToolInvocationState::Result
                || result.truncated
                || !record.release_started
                || binding.expected_taskrun_version < plan_commit_position
            {
                return Err(VerificationQueryError::InvalidBinding);
            }
            let encrypted_arguments = &record.arguments_payload;
            let arguments = self
                .provider
                .as_ref()
                .ok_or(VerificationQueryError::Unavailable)?
                .open_d2_tool_arguments(
                    encrypted_arguments.key,
                    binding.key.taskrun_id,
                    binding.key.attempt_id,
                    binding.key.cycle_id,
                    binding.key.proposal_index,
                    binding.semantic_digest,
                    &encrypted_arguments.payload,
                )
                .map_err(|_| VerificationQueryError::DigestMismatch)?;
            if hash(&arguments) != binding.arguments_digest {
                return Err(VerificationQueryError::DigestMismatch);
            }
            let encrypted_receipt = &result.receipt_payload;
            let receipt_bytes = self
                .provider
                .as_ref()
                .ok_or(VerificationQueryError::Unavailable)?
                .open_d2_tool_receipt(
                    encrypted_receipt.key,
                    binding.key.taskrun_id,
                    binding.key.attempt_id,
                    binding.key.cycle_id,
                    binding.key.proposal_index,
                    binding.semantic_digest,
                    &encrypted_receipt.payload,
                )
                .map_err(|_| VerificationQueryError::DigestMismatch)?;
            let claim = record
                .claim_assignment
                .as_ref()
                .ok_or(VerificationQueryError::InvalidBinding)?;
            let (receipt, receipt_content) = crate::safe_tool_helper::verify_bound_receipt(
                binding,
                &arguments,
                claim.fence.0,
                &receipt_bytes,
                result.digest,
                result.actual_length,
            )
            .map_err(|_| VerificationQueryError::DigestMismatch)?;
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            if !historical
                && (!coding
                    || (latest.get(&binding.target_name) == Some(&binding.key.proposal_index)
                        && last_command.is_none_or(|index| index <= binding.key.proposal_index)))
            {
                crate::application::exec_taskrun_worker::tool_invocation::target_snapshot::validate_d2_target_snapshot(
                &self.store,                &self.root_admission,
                workspace_id,
                binding,
                &arguments,
                &receipt,
            )
                .map_err(|_| VerificationQueryError::Stale)?;
            }
            let _receipt_content = receipt_content;
            let receipt_digest = hash(&receipt_bytes);
            let recorded = cycle
                .recorded_outcomes
                .iter()
                .find(|outcome| outcome.proposal_index == binding.key.proposal_index)
                .ok_or(VerificationQueryError::InvalidBinding)?;
            let expected_outcome = crate::application::d2_tool_outcome::expected_step_outcome(
                binding,
                result.digest,
                receipt_digest,
            )
            .map_err(|_| VerificationQueryError::InvalidBinding)?;
            let outcome_position = stream.events.iter().position(|event| {
                matches!(event.payload(), runne_domain::task_run::TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome }
                    if *cycle_id == cycle.cycle_id && outcome.proposal_index == binding.key.proposal_index)
            }).ok_or(VerificationQueryError::InvalidBinding)? as u64 + 1;
            if *recorded != expected_outcome || binding.expected_taskrun_version >= outcome_position
            {
                return Err(VerificationQueryError::DigestMismatch);
            }
            if coding {
                if binding.environment_id != crate::safe_tool_helper::coding_arguments::ENVIRONMENT
                {
                    return Err(VerificationQueryError::InvalidBinding);
                }
            } else {
                match binding.tool_name.as_str() {
                    "workspace.file.read"
                        if !saw_read
                            && binding.target_precondition.is_some()
                            && receipt.operation == "read" =>
                    {
                        saw_read = true
                    }
                    "workspace.file.create_new"
                        if !saw_create
                            && binding.target_precondition.is_none()
                            && receipt.operation == "create_new" =>
                    {
                        saw_create = true
                    }
                    _ => return Err(VerificationQueryError::InvalidBinding),
                }
            }
            if record.updated_at <= 0 {
                return Err(VerificationQueryError::InvalidBinding);
            }
            evaluated_at_unix_us = evaluated_at_unix_us.max(
                record
                    .updated_at
                    .checked_mul(1_000)
                    .ok_or(VerificationQueryError::InvalidBinding)?,
            );
            evidence.extend_from_slice(binding.semantic_digest.as_bytes());
            evidence.extend_from_slice(result.digest.as_bytes());
            evidence.extend_from_slice(hash(&receipt_bytes).as_bytes());
        }
        if (!coding && (!saw_read || !saw_create)) || evaluated_at_unix_us == 0 {
            return Err(VerificationQueryError::InvalidBinding);
        }
        assemble::assemble(
            taskrun_id,
            plan,
            stream.current_version,
            requested,
            evidence,
            evaluated_at_unix_us,
            coding,
        )
    }
}
