use super::*;
use crate::project_trust::{
    ManagedEffectClass, ManagedEffectDecision, ManagedEffectPolicyV1,
    ProjectTrustEffectPolicySnapshot, ProjectTrustRecord, ProjectTrustStatus,
    managed_effect_policy_digest_v2,
};
use runne_domain::{
    id::{AttemptId, IntegrityDigest, InvocationId, ProjectId, TaskRunId, WorkspaceId},
    task_run::{TaskRunExecutable, TaskRunLocalCommand},
};
use std::{collections::BTreeSet, str::FromStr};

#[path = "local_command_digest_tests.rs"]
mod digest_tests;
#[path = "local_command_validation_tests.rs"]
mod validation_tests;

pub(super) fn sample_input() -> LocalCommandPermissionBindingInputV1 {
    let project_id = ProjectId::from_bytes([1; 16]);
    let trust_project = crate::project_trust::ProjectTrustProjectId::from_bytes([1; 16]);
    let snapshot = ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Managed,
            instance_epoch: 7,
            revision: 3,
            managed_deny_mask: 0,
        },
        policy: ManagedEffectPolicyV1::all_allow(),
    };
    let permission_scope = PermissionScope {
        runtime_authority_id: crate::ports::RuntimeAuthorityId("runtime-a".into()),
        principal_id: runne_api::ApiPrincipalId::new("user:alice").unwrap(),
        workspace_id: WorkspaceId::from_bytes([7; 16]),
    };
    let scope = CompositeEffectScope {
        permission_scope: permission_scope.clone(),
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BroadSameUser,
            permissions: BTreeSet::from([
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]),
        },
        network: NetworkScope::None,
        managed_policy: ManagedPolicyCoverage::from_closed_snapshot(trust_project, &snapshot)
            .unwrap(),
        children: ChildDelegationScope::Unbounded,
        budget: EffectBudget {
            max_operations: None,
            max_bytes: None,
        },
        lifetime_ms: 30_000,
        containment: ContainmentStrategy::SameUserCompositeV2,
        protected_control_plane_policy_digest: digest(9),
    };
    let command = TaskRunLocalCommand::new(
        TaskRunExecutable::system_program("sh".into()).unwrap(),
        ".".into(),
        vec!["sh".into(), "-c".into(), "true".into()],
        vec![("LANG".into(), "C".into())],
    )
    .unwrap();
    let taskrun_id = TaskRunId::from_str("018f2e3a-7000-7000-8000-000000000001").unwrap();
    let attempt_id = AttemptId::from_str("018f2e3a-7000-7000-8000-000000000002").unwrap();
    let invocation_id = InvocationId::from_str("018f2e3a-7000-7000-8000-000000000003").unwrap();
    let closed_rules_digest = IntegrityDigest::from_bytes(
        managed_effect_policy_digest_v2(trust_project, &snapshot).unwrap(),
    );
    let approval = ApprovalBinding {
        action: PermissionAction::ProcessStart,
        normalized_arguments_digest: digest(1),
        tool_schema_digest: digest(2),
        principal_id: permission_scope.principal_id.clone(),
        invocation: InvocationIdentity {
            task_run_id: taskrun_id,
            attempt_id,
            invocation_id,
        },
        target_identity_digest: digest(3),
        target_version: 1,
        environment_digest: digest(4),
        cwd_identity_digest: digest(5),
        executable_digest: Some(digest(6)),
        composite_scope_digest: scope.digest().unwrap(),
        containment_version: scope.containment,
        relevant_policy_digest: scope.managed_policy.policy_digest(),
        expires_at_unix_ms: 10_000,
    };
    LocalCommandPermissionBindingInputV1 {
        selection: ModeSelection {
            scope: permission_scope,
            selected_mode: PermissionMode::AskAlways,
            preset_version: PresetVersion::V1,
            authorization_revision: 4,
            expires_at_unix_ms: Some(20_000),
        },
        assignment: crate::ports::TaskRunAssignmentIdentity {
            taskrun_id,
            attempt_id,
            node_id: crate::ports::ExecutionNodeId("node-a".into()),
            node_epoch: 2,
            fence: crate::ports::TaskRunFence(5),
        },
        claim_stream_version: 8,
        invocation_id,
        project_id,
        project_version: 6,
        workspace_version: 11,
        admitted_root_version: 3,
        held_root_identity_digest: digest(7),
        command_intent_digest: IntegrityDigest::from_bytes(command.intent_digest()),
        command,
        approval,
        scope,
        closed_rules_snapshot: snapshot,
        closed_rules_digest,
        limits: LocalInvocationLimitsV1::checked(65_536, 0, 5_000).unwrap(),
    }
}

pub(super) fn digest(byte: u8) -> IntegrityDigest {
    IntegrityDigest::from_bytes([byte; 32])
}

pub(super) fn refresh_managed_snapshot(input: &mut LocalCommandPermissionBindingInputV1) {
    let project =
        crate::project_trust::ProjectTrustProjectId::from_bytes(*input.project_id.as_bytes());
    input.scope.managed_policy =
        ManagedPolicyCoverage::from_closed_snapshot(project, &input.closed_rules_snapshot).unwrap();
    input.closed_rules_digest = IntegrityDigest::from_bytes(
        managed_effect_policy_digest_v2(project, &input.closed_rules_snapshot).unwrap(),
    );
    input.approval.relevant_policy_digest = input.scope.managed_policy.policy_digest();
    input.approval.composite_scope_digest = input.scope.digest().unwrap();
}

#[test]
fn checked_binding_keeps_workspace_and_admitted_root_versions_separate() {
    let binding = LocalCommandPermissionBindingV1::checked(sample_input()).unwrap();
    assert_eq!(binding.workspace_version(), 11);
    assert_eq!(binding.admitted_root_version(), 3);
    assert_eq!(binding.claim_stream_version(), 8);
    assert_eq!(binding.limits().admitted_invocations(), 1);
    assert_eq!(binding.closed_rules_encoder_version(), 2);
}
