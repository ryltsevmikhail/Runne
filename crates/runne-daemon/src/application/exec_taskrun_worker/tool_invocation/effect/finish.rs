use super::*;
use crate::application::exec_taskrun_worker::local::run::tool_executor as executor;
use crate::safe_tool_helper::{BindingV1, IdentityV1};
use runne_application::ports::EventStore;
use runne_application::ports::{ApplicationCommandContext, TaskRunAssignmentIdentity};
use runne_store::store::taskrun_tool_invocation::{ToolInvocationBindingV1, TrustedToolReceiptV1};

impl crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns {
    // These independently authenticated facts must reach the single durable settlement step.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_tool_effect(
        &self,
        context: &ApplicationCommandContext,
        assignment: &TaskRunAssignmentIdentity,
        binding: &ToolInvocationBindingV1,
        path: &str,
        args: &[u8],
        helper_binding: &BindingV1,
        root_file_identity: &IdentityV1,
        cleanup_proved: bool,
        after_exit_barrier: bool,
        run: Result<
            (i32, Vec<u8>, Vec<u8>),
            crate::application::exec_taskrun_worker::local::run::tool_executor::HelperRunFailure,
        >,
    ) -> Result<(), ()> {
        let provider = self.provider.as_ref().ok_or(())?;
        let (code, stdout, stderr) = match run {
            Ok((code, stdout, stderr)) => (code, stdout, stderr),
            Err(failure) => {
                audit::persist(
                    &self.store,
                    provider,
                    binding,
                    assignment,
                    audit::Observation {
                        reason: failure.reason as u8,
                        child_spawned: failure.child_spawned,
                        go_released: failure.go_released,
                        cleanup_proved,
                        stdout: &failure.stdout,
                        stderr: &failure.stderr,
                        stdout_truncated: failure.stdout_truncated,
                        stderr_truncated: failure.stderr_truncated,
                        stdout_observed_bytes: failure.stdout_observed_bytes,
                        stderr_observed_bytes: failure.stderr_observed_bytes,
                        observed_bytes_overflowed: failure.observed_bytes_overflowed,
                        stdout_eof: failure.stdout_eof,
                        stderr_eof: failure.stderr_eof,
                        exit_code: failure.exit_code,
                        helper_error_effect_started: audit::helper_error_effect_started(
                            &failure.stdout,
                        ),
                    },
                )?;
                return Err(());
            }
        };
        let persist_invalid = |reason, helper_error_effect_started| {
            audit::persist(
                &self.store,
                provider,
                binding,
                assignment,
                audit::Observation {
                    reason,
                    child_spawned: true,
                    go_released: true,
                    cleanup_proved,
                    stdout: &stdout,
                    stderr: &stderr,
                    stdout_truncated: false,
                    stderr_truncated: false,
                    stdout_observed_bytes: stdout.len() as u64,
                    stderr_observed_bytes: stderr.len() as u64,
                    observed_bytes_overflowed: false,
                    stdout_eof: true,
                    stderr_eof: true,
                    exit_code: Some(code),
                    helper_error_effect_started,
                },
            )
        };
        if !cleanup_proved {
            persist_invalid(10, audit::helper_error_effect_started(&stdout))?;
            return Err(());
        }
        if code != 0 {
            persist_invalid(11, audit::helper_error_effect_started(&stdout))?;
            return Err(());
        }
        if !after_exit_barrier {
            persist_invalid(15, audit::helper_error_effect_started(&stdout))?;
            return Err(());
        }
        let root = root_file_identity;
        let (receipt, actual_content) = match executor::verify_helper_stdout(
            &stdout,
            helper_binding,
            if binding.tool_name == "workspace.file.read" {
                "read"
            } else {
                "create_new"
            },
            path,
            root,
        ) {
            Ok(value) => value,
            Err(_) => {
                persist_invalid(12, audit::helper_error_effect_started(&stdout))?;
                return Err(());
            }
        };
        let raw_receipt = serde_json::to_vec(&receipt).map_err(|_| ())?;
        let content_digest = IntegrityDigest::from_bytes(Sha256::digest(&actual_content).into());
        let (verified, _) = match crate::safe_tool_helper::verify_bound_receipt(
            binding,
            args,
            assignment.fence.0,
            &raw_receipt,
            content_digest,
            actual_content.len() as u64,
        ) {
            Ok(value) => value,
            Err(_) => {
                persist_invalid(13, None)?;
                return Err(());
            }
        };
        if verified.truncated {
            persist_invalid(14, None)?;
            return Err(());
        }
        let stream = self
            .store
            .load_task_run(assignment.taskrun_id)
            .map_err(|_| ())?;
        let task = runne_domain::task_run::TaskRun::replay(&stream.events).map_err(|_| ())?;
        let workspace_id = task.snapshot_v1().workspace_id().ok_or(())?;
        if super::super::target_snapshot::validate_d2_target_snapshot(
            &self.root_admission,
            workspace_id,
            binding,
            args,
            &receipt,
        )
        .is_err()
        {
            // Preserve the exact helper receipt as encrypted audit evidence, but
            // stale targets cannot become authoritative results or continue.
            persist_invalid(16, None)?;
            return Err(());
        }
        let encrypted = provider.seal_d2_tool_receipt(
            binding.key.taskrun_id,
            binding.key.attempt_id,
            binding.key.cycle_id,
            binding.key.proposal_index,
            binding.semantic_digest,
            &raw_receipt,
        )?;
        self.store
            .record_taskrun_tool_result(
                TrustedToolReceiptV1 {
                    key: binding.key,
                    semantic_digest: binding.semantic_digest,
                    receipt_payload: encrypted,
                    result_digest: content_digest,
                    actual_length: actual_content.len() as u64,
                    truncated: false,
                    assignment: assignment.clone(),
                },
                now_millis(),
            )
            .map_err(|_| ())?;
        let persisted = self
            .store
            .load_taskrun_tool_invocation(binding.key)
            .map_err(|_| ())?
            .ok_or(())?;
        let stored_result = persisted.receipt.result.as_ref().ok_or(())?;
        if persisted.receipt.state
            != runne_store::store::taskrun_tool_invocation::ToolInvocationState::Result
            || stored_result.truncated
            || stored_result.digest != content_digest
            || stored_result.actual_length != actual_content.len() as u64
            || persisted.local_stop_state
                != runne_store::store::taskrun_tool_invocation::LocalToolStopState::ProvedEmpty
            || persisted.managed_area_identity != persisted.empty_proof_identity
        {
            return Err(());
        }
        let stream = self
            .store
            .load_task_run(assignment.taskrun_id)
            .map_err(|_| ())?;
        let receipt_digest = IntegrityDigest::from_bytes(Sha256::digest(&raw_receipt).into());
        let outcome = crate::application::d2_tool_outcome::expected_step_outcome(
            binding,
            content_digest,
            receipt_digest,
        )?;
        self.tool_loop_service
            .as_ref()
            .ok_or(())?
            .record_step_outcome(
                &Self::d2_command_context(
                    context.principal_id.clone(),
                    context.actor.clone(),
                    assignment.taskrun_id,
                    assignment.attempt_id,
                    Some(binding.key.cycle_id),
                    "record-step-outcome",
                    Some(binding.key.proposal_index),
                ),
                RecordStepOutcomeInput {
                    taskrun_id: assignment.taskrun_id,
                    expected_version: stream.current_version,
                    cycle_id: binding.key.cycle_id,
                    outcome,
                },
            )
            .map_err(|_| ())?;
        crate::application::exec_taskrun_worker::local::run::test_barrier::pause_at(
            crate::application::exec_taskrun_worker::local::run::test_barrier::Point::AfterDurableTerminal,
        )
        .map_err(|_| ())?;
        Ok(())
    }
}
