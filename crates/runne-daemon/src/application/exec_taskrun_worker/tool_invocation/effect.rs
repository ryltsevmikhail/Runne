use super::*;
use crate::safe_tool_helper::{BindingV1, IdentityV1};
use runne_application::{
    commands::RecordStepOutcomeInput,
    ports::{ApplicationCommandContext, TaskRunAssignmentIdentity},
};
use runne_domain::id::IntegrityDigest;
use runne_store::store::taskrun_tool_invocation::ToolInvocationBindingV1;
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;

use crate::application::exec_taskrun_worker::local::run::test_barrier;

#[path = "effect/audit.rs"]
mod audit;
#[path = "effect/finish.rs"]
mod finish;
#[path = "effect/launch.rs"]
mod launch;

impl super::super::DaemonAutomaticTaskRuns {
    pub(super) fn execute_approved_tool_effect(
        &self,
        context: &ApplicationCommandContext,
        assignment: &TaskRunAssignmentIdentity,
        workspace_id: runne_domain::id::WorkspaceId,
        binding: &ToolInvocationBindingV1,
        prepared: &super::permission::PreparedPermissionInvocation,
    ) -> Result<(), ()> {
        use crate::application::exec_taskrun_worker::local::run::tool_executor as executor;
        use runne_application::ports::EventStore;
        use runne_platform::process_managed_area::LinuxManagedAreaRoot;

        super::super::provider::d2_stage("effect_epoch_check");
        if self.current_epoch.load(Ordering::Acquire) != assignment.node_epoch {
            return Err(());
        }
        let stream = self
            .store
            .load_task_run(assignment.taskrun_id)
            .map_err(|_| ())?;
        if stream.current_version != binding.expected_taskrun_version {
            return Err(());
        }
        let provider = self.provider.as_ref().ok_or(())?;
        let record = self
            .store
            .load_taskrun_tool_invocation(binding.key)
            .map_err(|_| ())?
            .ok_or(())?;
        super::super::provider::d2_stage("effect_open_arguments");
        if record.binding.semantic_digest != binding.semantic_digest
            || record.binding.approval_digest != binding.approval_digest
        {
            return Err(());
        }
        let args = provider
            .open_d2_tool_arguments(
                record.arguments_payload.key,
                binding.key.taskrun_id,
                binding.key.attempt_id,
                binding.key.cycle_id,
                binding.key.proposal_index,
                binding.semantic_digest,
                &record.arguments_payload.payload,
            )
            .map_err(|_| ())?;
        if Sha256::digest(&args).as_slice() != binding.arguments_digest.as_bytes() {
            return Err(());
        }
        let helper_digest = super::permission_identity::command_helper_digest(
            self.permission_admission.as_ref().ok_or(())?,
            &binding.tool_name,
        )?;
        let (path, content) = parse_arguments(
            &runne_runtime::provider_tool::RuntimeToolCall {
                call_id: binding.call_id.clone(),
                tool_name: binding.tool_name.clone(),
                arguments_json: String::from_utf8(args.to_vec()).map_err(|_| ())?,
            },
            binding.environment_id == crate::safe_tool_helper::coding_arguments::ENVIRONMENT,
        )?;
        super::super::provider::d2_stage("effect_target_admission");
        self.root_admission
            .admit_coding_tool_target(workspace_id, &binding.tool_name, &path)
            .map_err(|_| ())?;
        super::super::provider::d2_stage("effect_target_snapshot");
        let (files, root_file_identity, target) = self
            .root_admission
            .with_local_command_root(workspace_id, |root, wv, _, rv, ri, admission| {
                let files = root
                    .open_linux_command_workspace(std::path::Path::new("."))
                    .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Unavailable)?;
                let (device, inode) = executor::descriptor_identity(files.workspace())
                    .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Unavailable)?;
                let target = if binding.environment_id
                    == crate::safe_tool_helper::coding_arguments::ENVIRONMENT
                {
                    crate::safe_tool_helper::coding_fs::capture(
                        files.workspace(),
                        &binding.tool_name,
                        &path,
                    )
                    .map_err(|_| ())
                } else {
                    executor::capture_target_precondition(&files, &binding.tool_name, &path)
                }
                .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)?;
                let target_digest = target.as_ref().map(|v| {
                    IntegrityDigest::from_bytes(
                        Sha256::digest(serde_json::to_vec(v).expect("version serializes")).into(),
                    )
                });
                if target_digest != binding.target_precondition
                    || rv != binding.root_revision
                    || ri != *binding.root_identity.as_bytes()
                {
                    return Err(runne_platform_desktop::RootHandleBrokerError::Rejected);
                }
                let approved = approval_digest(
                    binding.key.taskrun_id,
                    binding.key.attempt_id,
                    binding.key.cycle_id,
                    binding.key.proposal_index,
                    binding.expected_taskrun_version,
                    &binding.call_id,
                    &binding.tool_name,
                    &binding.tool_revision,
                    &binding.environment_id,
                    &binding.approval_principal_id,
                    binding.schema_digest.as_bytes(),
                    &args,
                    target_digest.as_ref().map(IntegrityDigest::as_bytes),
                    binding.root_identity.as_bytes(),
                    rv,
                    wv,
                    admission.token.instance_epoch,
                    admission.token.revision,
                    binding.approval_expires_at,
                    helper_digest.as_ref().map(IntegrityDigest::as_bytes),
                );
                if approved != *binding.approval_digest.as_bytes() {
                    return Err(runne_platform_desktop::RootHandleBrokerError::Rejected);
                }
                Ok((files, IdentityV1 { device, inode }, target))
            })
            .map_err(|_| ())?;
        super::super::provider::d2_stage("effect_trust_lease");
        test_barrier::pause_at_for_human(
            test_barrier::Point::AfterApprovalBeforeLease,
            prepared.requires_human,
        )
        .map_err(|_| ())?;
        super::super::provider::d2_stage("effect_claim");
        let stream = self
            .store
            .load_task_run(assignment.taskrun_id)
            .map_err(|_| ())?;
        if stream.current_version != binding.expected_taskrun_version {
            return Err(());
        }
        let claim = self
            .store
            .claim_taskrun_tool_invocation(
                binding.key,
                binding.semantic_digest,
                assignment,
                stream.current_version,
                now_millis(),
            )
            .map_err(|_| ())?;
        if claim.state != runne_store::store::taskrun_tool_invocation::ToolInvocationState::Claimed
        {
            return Err(());
        }
        test_barrier::pause_at_for_human(
            test_barrier::Point::AfterClaimBeforeArea,
            prepared.requires_human,
        )
        .map_err(|_| ())?;
        super::super::provider::d2_stage("effect_area_create");
        let area_root = LinuxManagedAreaRoot::open_current_cgroup().map_err(|_| ())?;
        let area = executor::new_area(
            &area_root,
            binding.key.taskrun_id,
            binding.key.attempt_id,
            binding.key.managed_area_nonce(binding.semantic_digest),
        )
        .map_err(|_| ())?;
        let area_identity = area.identity();
        self.store
            .record_taskrun_tool_area_launch(
                binding.key,
                binding.semantic_digest,
                assignment,
                area_identity,
                now_millis(),
            )
            .map_err(|_| ())?;
        super::super::provider::d2_stage("effect_area_recorded");
        let helper_binding = super::permission_build::helper_binding(binding, assignment)?;
        let input = super::permission_build::helper_request(
            binding,
            assignment,
            root_file_identity.clone(),
            target,
            &content,
        )?;
        drop(files);
        let run = self.run_d2_tool_helper(&input, &area, assignment, binding, prepared);
        let after_exit_barrier =
            crate::application::exec_taskrun_worker::local::run::test_barrier::pause_at(
                crate::application::exec_taskrun_worker::local::run::test_barrier::Point::AfterExit,
            )
            .is_ok();
        let local_stop = area.prove_empty();
        let cleanup_proved = local_stop.is_ok();
        if let Ok(empty) = &local_stop {
            self.store
                .record_taskrun_tool_area_stopped(
                    binding.key,
                    binding.semantic_digest,
                    assignment,
                    area_identity,
                    empty,
                    now_millis(),
                )
                .map_err(|_| ())?;
        }
        drop(local_stop);
        let result = self.finish_tool_effect(
            context,
            assignment,
            binding,
            &path,
            &args,
            &helper_binding,
            &root_file_identity,
            cleanup_proved,
            after_exit_barrier,
            run,
        );
        if cleanup_proved && area.remove_empty().is_err() {
            super::super::provider::d2_stage("effect_area_remove_failed");
        }
        result
    }
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn helper_terminal_matches(
    observed: &runne_platform::local_command_linux::PermissionHelperObservationV1,
    binding: &ToolInvocationBindingV1,
    assignment: &TaskRunAssignmentIdentity,
    expected: &BindingV1,
    root: &IdentityV1,
    path: &str,
) -> bool {
    use runne_platform::local_command_linux::PermissionHelperOperationV1 as Operation;
    let operation_matches = matches!(
        (binding.tool_name.as_str(), observed.operation()),
        ("workspace.file.read", Operation::Read)
            | ("workspace.file.create_new", Operation::CreateNew)
            | ("workspace.files.list", Operation::List)
            | ("workspace.files.search", Operation::Search)
            | ("workspace.file.replace", Operation::Replace)
            | ("workspace.command.run", Operation::Command)
    );
    let actual = observed.binding();
    operation_matches
        && observed.path() == path
        && observed.arguments_digest() == binding.arguments_digest.as_bytes()
        && observed.root_identity() == (root.device, root.inode)
        && actual.taskrun_id == expected.taskrun_id
        && actual.attempt_id == expected.attempt_id
        && actual.cycle_id == expected.cycle_id
        && actual.proposal_index == expected.proposal_index
        && actual.taskrun_version == expected.taskrun_version
        && actual.assignment_fence == assignment.fence.0
        && actual.invocation_digest == expected.invocation_digest
        && actual.environment_digest == expected.environment_digest
        && actual.approval_digest == expected.approval_digest
        && actual.expires_at_unix_ms == expected.expires_at_unix_ms
}
