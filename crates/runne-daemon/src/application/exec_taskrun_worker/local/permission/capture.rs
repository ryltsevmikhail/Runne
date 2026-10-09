use super::*;
use runne_application::permission_modes::{
    ApprovalBinding, InvocationIdentity, LocalCommandPermissionBindingInputV1,
    LocalCommandPermissionBindingV1, LocalInvocationLimitsV1, PermissionAction, PermissionScope,
};
use runne_application::ports::{
    TaskRunAssignmentIdentity, TaskRunExecutionInputPort, TaskRunQueueCandidate,
};
use runne_application::project_trust::ProjectTrustProjectId;
use runne_domain::id::{IntegrityDigest, InvocationId};
use runne_domain::task_run::TaskRunExecutable;
use runne_platform::local_command_linux::{
    LinuxCommandExecutable, LinuxCommandSpec, PreparedPermissionTargetV1, SealedExecutableSnapshot,
};
use runne_platform_desktop::LinuxCommandFiles;
use runne_store::store::{ManagedIdentityMetadata, PermissionModeAuthorityContext};
use std::ffi::OsString;

#[path = "invocation_scope.rs"]
mod invocation_scope;

pub(super) struct PreparedCurrentCommand {
    pub(super) identity: TaskRunAssignmentIdentity,
    pub(super) claimed_version: u64,
    pub(super) workspace: runne_domain::id::WorkspaceId,
    pub(super) principal: ApiPrincipalId,
    pub(super) command: runne_domain::task_run::TaskRunLocalCommand,
    pub(super) _files: LinuxCommandFiles,
    pub(super) target: PreparedPermissionTargetV1,
    pub(super) binding: LocalCommandPermissionBindingV1,
}

pub(super) fn prepare(
    worker: &DaemonAutomaticTaskRuns,
    candidate: TaskRunQueueCandidate,
) -> Result<PreparedCurrentCommand, AutomaticTaskRunError> {
    let context = DaemonAutomaticTaskRuns::runtime_context();
    let receipt = worker
        .taskruns
        .claim_task_run(
            &context,
            runne_application::service::ClaimTaskRunInput {
                taskrun_id: candidate.taskrun_id,
                expected_version: candidate.current_version,
                node_id: worker.node_id.clone(),
                node_epoch: worker
                    .current_epoch
                    .load(std::sync::atomic::Ordering::Acquire),
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 300_000,
            },
            &worker.store,
        )
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let receipt = match receipt {
        runne_application::ports::TaskRunClaimResult::Committed(value)
        | runne_application::ports::TaskRunClaimResult::Duplicate(value) => value,
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id: receipt.taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: receipt.node_id,
        node_epoch: receipt.node_epoch,
        fence: receipt.fence,
    };
    if identity.node_epoch
        != worker
            .current_epoch
            .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err(AutomaticTaskRunError::Unavailable);
    }
    let claimed = worker
        .store
        .read_taskrun_execution_input(identity.clone(), receipt.new_version)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    #[cfg(feature = "test-support")]
    if super::super::run::test_barrier::pause_at(
        super::super::run::test_barrier::Point::AfterClaimBeforeArea,
    )
    .is_err()
    {
        return Err(AutomaticTaskRunError::Uncertain);
    }
    let workspace = claimed.workspace_id;
    let principal = ApiPrincipalId::new(claimed.principal_id.0)
        .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
    let command = claimed
        .input
        .local_command()
        .cloned()
        .ok_or(AutomaticTaskRunError::RejectedBeforeEffect)?;
    let prepared_root = worker.root_admission.with_local_command_root(
        workspace,
        |root, wv, project, rv, ri, admission| {
            let files = match command.executable() {
                TaskRunExecutable::WorkspaceRelative(path) => root.open_linux_command_files(
                    std::path::Path::new(&path),
                    std::path::Path::new(command.cwd()),
                ),
                TaskRunExecutable::SystemProgram(catalog_id) => root
                    .open_linux_system_command_files(
                        catalog_id,
                        std::path::Path::new(command.cwd()),
                    ),
            }
            .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)?;
            let executable = SealedExecutableSnapshot::from_held_file(files.executable())
                .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)?;
            let preparation = worker
                .store
                .local_permission_preparation()
                .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Unavailable)?;
            let spec = LinuxCommandSpec {
                executable: LinuxCommandExecutable::SealedSnapshot(&executable),
                workspace: files.workspace(),
                cwd: files.cwd(),
                argv: command.argv().iter().map(OsString::from).collect(),
                env: command
                    .env()
                    .iter()
                    .map(|(key, value)| (OsString::from(key), OsString::from(value)))
                    .collect(),
            };
            spec.preflight()
                .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)?;
            let target = preparation
                .prepare_target(command.clone(), files.workspace(), files.cwd(), executable)
                .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)?;
            Ok((files, target, wv, project, rv, ri, admission.token))
        },
    );
    let (files, target, workspace_version, project_bytes, root_version, root_identity, trust_token) =
        match prepared_root {
            Ok(prepared) => prepared,
            Err(runne_platform_desktop::RootHandleBrokerError::Rejected) => {
                worker.release_before_effect(identity.clone(), claimed.stream_version)?;
                return Err(AutomaticTaskRunError::RejectedBeforeEffect);
            }
            Err(error) => return Err(super::map_root_error(error)),
        };
    let project = ProjectTrustProjectId::from_bytes(project_bytes);
    let lease = worker
        .root_admission
        .acquire_local_command_effect_lease(workspace, trust_token)
        .map_err(super::map_root_error)?;
    let trust = lease
        .snapshot()
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let scope = PermissionScope {
        runtime_authority_id: worker.store.runtime_authority_id().clone(),
        principal_id: principal.clone(),
        workspace_id: workspace,
    };
    let authority = PermissionModeAuthorityContext::new(&principal, project, lease.as_ref(), None);
    #[cfg(feature = "test-support")]
    super::super::diagnostic::seed_legacy_selection(worker, &scope, project, lease.as_ref());
    let selected = worker
        .store
        .load_permission_mode_selection_with_managed_identity(&scope, &principal, &authority)
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let managed = match selected.identity {
        ManagedIdentityMetadata::ClosedRulesV2(value) => value,
        ManagedIdentityMetadata::LegacyRecordV1(_) => {
            #[cfg(feature = "test-support")]
            super::super::diagnostic::stage("current_legacy_identity_rejected");
            drop(lease);
            worker.release_before_effect(identity.clone(), claimed.stream_version)?;
            return Err(AutomaticTaskRunError::RejectedBeforeEffect);
        }
    };
    if managed.project_id != project_bytes || managed.snapshot != trust {
        #[cfg(feature = "test-support")]
        super::super::diagnostic::stage("current_managed_identity_mismatch");
        drop(lease);
        worker.release_before_effect(identity.clone(), claimed.stream_version)?;
        return Err(AutomaticTaskRunError::RejectedBeforeEffect);
    }
    let native = worker
        .permission_admission
        .as_ref()
        .ok_or(AutomaticTaskRunError::Unavailable)?;
    let effective_scope = invocation_scope::invocation_scope(
        &selected.selection,
        scope,
        ProjectTrustProjectId::from_bytes(project_bytes),
        &managed.snapshot,
        native.as_ref(),
    )?;
    let limits = LocalInvocationLimitsV1::checked(64 * 1024, 64 * 1024, 120_000)
        .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
    let invocation = InvocationId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let observation = target.observation();
    let expires_at = selected
        .selection
        .expires_at_unix_ms
        .unwrap_or_else(|| super::now_millis().saturating_add(120_000))
        .min(super::now_millis().saturating_add(120_000));
    let scope_digest = effective_scope
        .digest()
        .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
    let approval = ApprovalBinding {
        action: PermissionAction::ProcessStart,
        normalized_arguments_digest: IntegrityDigest::from_bytes(
            *observation.normalized_arguments_digest(),
        ),
        tool_schema_digest: IntegrityDigest::from_bytes(*observation.schema_digest()),
        principal_id: principal.clone(),
        invocation: InvocationIdentity {
            task_run_id: identity.taskrun_id,
            attempt_id: identity.attempt_id,
            invocation_id: invocation,
        },
        target_identity_digest: IntegrityDigest::from_bytes(*observation.target_identity()),
        target_version: observation.target_version(),
        environment_digest: IntegrityDigest::from_bytes(*observation.environment_digest()),
        cwd_identity_digest: IntegrityDigest::from_bytes(*observation.cwd_identity()),
        executable_digest: Some(IntegrityDigest::from_bytes(
            *observation.executable_digest(),
        )),
        composite_scope_digest: scope_digest,
        containment_version: effective_scope.containment,
        relevant_policy_digest: effective_scope.managed_policy.policy_digest(),
        expires_at_unix_ms: expires_at,
    };
    let binding = LocalCommandPermissionBindingV1::checked(LocalCommandPermissionBindingInputV1 {
        selection: selected.selection,
        assignment: identity.clone(),
        claim_stream_version: claimed.stream_version,
        invocation_id: invocation,
        project_id: runne_domain::id::ProjectId::from_bytes(project_bytes),
        project_version: managed.project_version,
        workspace_version,
        admitted_root_version: root_version,
        held_root_identity_digest: IntegrityDigest::from_bytes(root_identity),
        command_intent_digest: IntegrityDigest::from_bytes(command.intent_digest()),
        command: command.clone(),
        approval,
        scope: effective_scope,
        closed_rules_snapshot: managed.snapshot,
        closed_rules_digest: managed.canonical_digest,
        limits,
    })
    .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
    drop(lease);
    worker
        .store
        .capture_local_command_permission(&binding, observation)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    Ok(PreparedCurrentCommand {
        identity,
        claimed_version: claimed.stream_version,
        workspace,
        principal,
        command,
        _files: files,
        target,
        binding,
    })
}
