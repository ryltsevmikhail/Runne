use crate::{permission_modes::*, ports::RuntimeAuthorityId, project_trust::*};
use runne_api::ApiPrincipalId;
use runne_domain::id::{IntegrityDigest, WorkspaceId};

fn original() -> (
    ProjectTrustProjectId,
    CompositeEffectScope,
    ProjectTrustEffectPolicySnapshot,
) {
    let project = ProjectTrustProjectId::from_bytes([1; 16]);
    let snapshot = ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Managed,
            instance_epoch: 9,
            revision: 3,
            managed_deny_mask: 0,
        },
        policy: ManagedEffectPolicyV1::all_allow(),
    };
    let scope = CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: RuntimeAuthorityId("scope-test".into()),
            principal_id: ApiPrincipalId::new("scope-user").unwrap(),
            workspace_id: WorkspaceId::from_bytes([2; 16]),
        },
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BroadSameUser,
            permissions: [
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]
            .into_iter()
            .collect(),
        },
        network: NetworkScope::None,
        managed_policy: ManagedPolicyCoverage::from_closed_snapshot(project, &snapshot).unwrap(),
        children: ChildDelegationScope::Unbounded,
        budget: EffectBudget {
            max_operations: None,
            max_bytes: None,
        },
        lifetime_ms: 1000,
        containment: ContainmentStrategy::SameUserCompositeV1,
        protected_control_plane_policy_digest: IntegrityDigest::from_bytes([3; 32]),
    };
    (project, scope, snapshot)
}

#[test]
fn original_semantics_reuses_provided_classes_and_valid_unsupported() {
    let (project, mut scope, snapshot) = original();
    let value = derive_original_semantics_v1(project, &scope, &snapshot, 1, 2, 1).unwrap();
    let RetainedScopeSemanticsV1::SupportedV1(value) = value else {
        panic!("supported broad scope")
    };
    assert_eq!(value.provided, [true, true, true, true, true, false]);
    assert_eq!(
        value.decisions,
        [
            Some(ManagedEffectDecision::Allow),
            Some(ManagedEffectDecision::Allow),
            Some(ManagedEffectDecision::Allow),
            Some(ManagedEffectDecision::Allow),
            Some(ManagedEffectDecision::Allow),
            None
        ]
    );
    scope.filesystem.posture = FilesystemPosture::None;
    scope.containment = ContainmentStrategy::WorkspaceBoundV1;
    scope.budget.max_operations = Some(0);
    scope.children = ChildDelegationScope::MaxDepth(0);
    assert!(matches!(
        derive_original_semantics_v1(project, &scope, &snapshot, 1, 2, 1),
        Ok(RetainedScopeSemanticsV1::UnsupportedV1(_))
    ));
}

#[test]
fn revision_and_unused_decision_preserve_only_data_compatibility() {
    let (project, scope, snapshot) = original();
    let later = ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            revision: 4,
            ..snapshot.record
        },
        policy: snapshot
            .policy
            .with_decision(ManagedEffectClass::NetworkUse, ManagedEffectDecision::Deny),
    };
    let mut current = scope.clone();
    current.managed_policy = ManagedPolicyCoverage::from_closed_snapshot(project, &later).unwrap();
    assert!(matches!(
        assess_retained_scope_compatibility_v1(
            project, &scope, &snapshot, project, &current, &later, 1, 2, 1
        ),
        RetainedScopeCompatibilityV1::Compatible { .. }
    ));
    let changed = ProjectTrustEffectPolicySnapshot {
        policy: later
            .policy
            .with_decision(ManagedEffectClass::ProcessStart, ManagedEffectDecision::Ask),
        ..later
    };
    current.managed_policy =
        ManagedPolicyCoverage::from_closed_snapshot(project, &changed).unwrap();
    assert_eq!(
        assess_retained_scope_compatibility_v1(
            project, &scope, &snapshot, project, &current, &changed, 1, 2, 1
        ),
        RetainedScopeCompatibilityV1::RelevantChange
    );
    current.lifetime_ms += 1;
    assert_eq!(
        assess_retained_scope_compatibility_v1(
            project, &scope, &snapshot, project, &current, &changed, 1, 2, 1
        ),
        RetainedScopeCompatibilityV1::IdentityChanged
    );
}

#[test]
fn invalid_closed_project_and_versions_are_not_unsupported() {
    let (project, scope, snapshot) = original();
    assert_eq!(
        derive_original_semantics_v1(project, &scope, &snapshot, 2, 2, 1),
        Err(InvalidOriginalSemanticsV1::UnsupportedVersion)
    );
    assert!(
        derive_original_semantics_v1(
            ProjectTrustProjectId::from_bytes([0; 16]),
            &scope,
            &snapshot,
            1,
            2,
            1
        )
        .is_err()
    );
    let other = ProjectTrustProjectId::from_bytes([7; 16]);
    let mut current = scope.clone();
    current.managed_policy = ManagedPolicyCoverage::from_closed_snapshot(other, &snapshot).unwrap();
    assert_eq!(
        assess_retained_scope_compatibility_v1(
            project, &scope, &snapshot, other, &current, &snapshot, 1, 2, 1
        ),
        RetainedScopeCompatibilityV1::IdentityChanged
    );
}

#[test]
fn different_projects_remain_identity_changes_for_valid_unsupported_shapes() {
    let (project, mut scope, snapshot) = original();
    scope.filesystem.posture = FilesystemPosture::None;
    scope.containment = ContainmentStrategy::WorkspaceBoundV1;
    let other = ProjectTrustProjectId::from_bytes([7; 16]);
    let mut current = scope.clone();
    current.managed_policy = ManagedPolicyCoverage::from_closed_snapshot(other, &snapshot).unwrap();
    assert_eq!(
        assess_retained_scope_compatibility_v1(
            project, &scope, &snapshot, other, &current, &snapshot, 1, 2, 1
        ),
        RetainedScopeCompatibilityV1::IdentityChanged
    );
}
