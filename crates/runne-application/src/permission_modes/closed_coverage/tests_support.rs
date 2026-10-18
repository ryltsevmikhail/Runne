use crate::permission_modes::{
    ApprovalBinding, ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, EffectBudget,
    FilesystemPermission, FilesystemPosture, FilesystemRoot, FilesystemScope, InvocationIdentity,
    InvocationPolicyRequest, ManagedDisposition, ManagedPolicyCoverage, ManagedPolicyEvaluation,
    ModeSelection, NativeAdmissionError, NativeScopeAdmissionPort, NetworkScope, PermissionAction,
    PermissionMode, PermissionScope, PolicyEvaluationInput, PresetVersion, ResolutionState,
    ResourceFacts, Sensitivity, SizeBound, TargetState, WorkspaceRelation, admit_effective_mode,
    admit_invocation_scope,
};
use crate::project_trust::{
    ManagedEffectDecision, ManagedEffectPolicyV1, ProjectTrustEffectPolicySnapshot,
    ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus,
};
use runne_domain::id::{AttemptId, IntegrityDigest, InvocationId, TaskRunId, WorkspaceId};
use std::collections::BTreeSet;
use std::str::FromStr;

pub(super) fn input_for_read(rules: [ManagedEffectDecision; 6]) -> PolicyEvaluationInput {
    input_for_scope(
        bounded_scope([FilesystemPermission::Read], rules),
        PermissionMode::RiskBased,
    )
}

pub(super) fn input_for_scope(
    scope: CompositeEffectScope,
    mode: PermissionMode,
) -> PolicyEvaluationInput {
    let port = MockAdmission;
    let selection = ModeSelection {
        scope: scope.permission_scope.clone(),
        selected_mode: mode,
        preset_version: PresetVersion::V1,
        authorization_revision: 1,
        expires_at_unix_ms: None,
    };
    let effective = admit_effective_mode(mode, PresetVersion::V1, &scope, &port).unwrap();
    let scope_digest = scope.digest().unwrap();
    let candidate_binding = ApprovalBinding {
        action: PermissionAction::FsRead,
        normalized_arguments_digest: digest(1),
        tool_schema_digest: digest(2),
        principal_id: scope.permission_scope.principal_id.clone(),
        invocation: InvocationIdentity {
            task_run_id: TaskRunId::from_str("018f2e3a-7000-7000-8000-000000000001").unwrap(),
            attempt_id: AttemptId::from_str("018f2e3a-7000-7000-8000-000000000002").unwrap(),
            invocation_id: InvocationId::from_str("018f2e3a-7000-7000-8000-000000000003").unwrap(),
        },
        target_identity_digest: digest(3),
        target_version: 1,
        environment_digest: digest(4),
        cwd_identity_digest: digest(5),
        executable_digest: None,
        composite_scope_digest: scope_digest,
        containment_version: scope.containment,
        relevant_policy_digest: scope.managed_policy.policy_digest(),
        expires_at_unix_ms: 1_000,
    };
    let root = FilesystemRoot::new(digest(3), vec!["source.rs".into()]).unwrap();
    let resource = ResourceFacts {
        workspace: WorkspaceRelation::Inside,
        sensitivity: Sensitivity::Nonsensitive,
        size: SizeBound::Bounded,
        resolution: ResolutionState::HeldSafe,
        resolved_path: Some(root),
        target: TargetState::Existing,
        object: crate::permission_modes::ObjectKind::RegularFile,
        executable: false,
    };
    PolicyEvaluationInput {
        selection,
        effective,
        effective_scope: scope.clone(),
        invocation: InvocationPolicyRequest {
            action: PermissionAction::FsRead,
            resource,
            composite_scope: scope.clone(),
            candidate_binding,
            approved_binding: None,
            native_admission: Some(admit_invocation_scope(&scope, &port).unwrap()),
        },
        managed: ManagedPolicyEvaluation {
            scope_digest,
            policy_digest: scope.managed_policy.policy_digest(),
            disposition: ManagedDisposition::Allow,
        },
        now_unix_ms: 100,
    }
}

pub(super) struct MockAdmission;

impl NativeScopeAdmissionPort for MockAdmission {
    fn admit_mode_readiness(
        &self,
        _mode: PermissionMode,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        Ok(digest(90))
    }

    fn admit_scope(
        &self,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        Ok(digest(91))
    }
}

pub(super) struct UnavailableAdmission;

impl NativeScopeAdmissionPort for UnavailableAdmission {
    fn admit_mode_readiness(
        &self,
        _mode: PermissionMode,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        Err(NativeAdmissionError::EnforcementUnavailable)
    }

    fn admit_scope(
        &self,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        Err(NativeAdmissionError::EnforcementUnavailable)
    }
}

pub(super) fn digest(value: u8) -> IntegrityDigest {
    IntegrityDigest::from_bytes([value; 32])
}

pub(super) fn decisions(value: ManagedEffectDecision) -> [ManagedEffectDecision; 6] {
    [value; 6]
}

pub(super) fn project() -> ProjectTrustProjectId {
    ProjectTrustProjectId::from_bytes([1; 16])
}

pub(super) fn other_project() -> ProjectTrustProjectId {
    ProjectTrustProjectId::from_bytes([2; 16])
}

pub(super) fn zero_project() -> ProjectTrustProjectId {
    ProjectTrustProjectId::from_bytes([0; 16])
}

pub(super) fn snapshot(
    rules: [ManagedEffectDecision; 6],
    revision: u64,
) -> ProjectTrustEffectPolicySnapshot {
    ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Managed,
            instance_epoch: 7,
            revision,
            managed_deny_mask: 0,
        },
        policy: ManagedEffectPolicyV1::new(1, rules),
    }
}

pub(super) fn broad_scope(
    network: NetworkScope,
    rules: [ManagedEffectDecision; 6],
) -> CompositeEffectScope {
    CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: crate::ports::RuntimeAuthorityId("closed-test".into()),
            principal_id: runne_api::ApiPrincipalId::new("user:closed-test").unwrap(),
            workspace_id: workspace(1),
        },
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BroadSameUser,
            permissions: BTreeSet::from([
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]),
        },
        network,
        managed_policy: ManagedPolicyCoverage::from_closed_snapshot(project(), &snapshot(rules, 9))
            .unwrap(),
        children: ChildDelegationScope::Unbounded,
        budget: EffectBudget {
            max_operations: None,
            max_bytes: None,
        },
        lifetime_ms: 30_000,
        containment: ContainmentStrategy::SameUserCompositeV1,
        protected_control_plane_policy_digest: IntegrityDigest::from_bytes([8; 32]),
    }
}

pub(super) fn workspace(value: u8) -> WorkspaceId {
    let mut bytes = [value; 16];
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    WorkspaceId::from_bytes(bytes)
}

pub(super) fn bounded_scope(
    rights: impl IntoIterator<Item = FilesystemPermission>,
    rules: [ManagedEffectDecision; 6],
) -> CompositeEffectScope {
    let root = FilesystemRoot::new(IntegrityDigest::from_bytes([3; 32]), Vec::new()).unwrap();
    CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: crate::ports::RuntimeAuthorityId("closed-test".into()),
            principal_id: runne_api::ApiPrincipalId::new("user:closed-test").unwrap(),
            workspace_id: workspace(1),
        },
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BoundedRoots(BTreeSet::from([root])),
            permissions: rights.into_iter().collect(),
        },
        network: NetworkScope::None,
        managed_policy: ManagedPolicyCoverage::from_closed_snapshot(project(), &snapshot(rules, 9))
            .unwrap(),
        children: ChildDelegationScope::None,
        budget: EffectBudget {
            max_operations: Some(1),
            max_bytes: Some(4096),
        },
        lifetime_ms: 30_000,
        containment: ContainmentStrategy::WorkspaceBoundV1,
        protected_control_plane_policy_digest: IntegrityDigest::from_bytes([8; 32]),
    }
}
