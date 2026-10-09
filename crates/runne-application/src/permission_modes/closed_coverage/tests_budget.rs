use crate::permission_modes::{
    ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, EffectBudget,
    FilesystemPermission, FilesystemPosture, FilesystemRoot, FilesystemScope,
    ManagedPolicyCoverage, NetworkScope, PermissionScope, ScopeError,
};
use crate::project_trust::{
    ManagedEffectClass, ManagedEffectDecision, ManagedEffectPolicyV1,
    ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, ProjectTrustRecord,
    ProjectTrustStatus,
};
use runne_domain::id::{IntegrityDigest, WorkspaceId};
use std::collections::BTreeSet;

fn broad_scope(network: NetworkScope) -> CompositeEffectScope {
    let mut workspace = [1; 16];
    workspace[6] = 0x70;
    workspace[8] = 0x80;
    let mut rules = [ManagedEffectDecision::Allow; 6];
    if network == NetworkScope::None {
        rules[ManagedEffectClass::NetworkUse.tag() as usize - 1] = ManagedEffectDecision::Deny;
    }
    let snapshot = ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Managed,
            instance_epoch: 7,
            revision: 9,
            managed_deny_mask: 0,
        },
        policy: ManagedEffectPolicyV1::new(1, rules),
    };
    CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: crate::ports::RuntimeAuthorityId("quota-test".into()),
            principal_id: runne_api::ApiPrincipalId::new("user:quota-test").unwrap(),
            workspace_id: WorkspaceId::from_bytes(workspace),
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
        managed_policy: ManagedPolicyCoverage::from_closed_snapshot(
            ProjectTrustProjectId::from_bytes([1; 16]),
            &snapshot,
        )
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

#[test]
fn closed_broad_rejects_each_finite_quota_for_both_network_postures() {
    for network in [NetworkScope::None, NetworkScope::BroadSameUser] {
        for value in [0, 1, u64::MAX] {
            let mut operations = broad_scope(network);
            operations.budget.max_operations = Some(value);
            assert_eq!(
                operations.validate(),
                Err(ScopeError::UnsupportedBroadEffectQuota),
                "operations={value}, network={network:?}"
            );

            let mut bytes = broad_scope(network);
            bytes.budget.max_bytes = Some(value);
            assert_eq!(
                bytes.validate(),
                Err(ScopeError::UnsupportedBroadEffectQuota),
                "bytes={value}, network={network:?}"
            );
        }
    }
}

#[test]
fn closed_broad_none_none_and_bounded_quotas_remain_supported() {
    for network in [NetworkScope::None, NetworkScope::BroadSameUser] {
        let scope = broad_scope(network);
        assert_eq!(
            scope.budget,
            EffectBudget {
                max_operations: None,
                max_bytes: None,
            }
        );
        scope.validate().unwrap();
        assert!(scope.digest().is_ok());
        assert!(scope.managed_policy.supports_closed_scope(&scope));
    }

    let mut bounded = broad_scope(NetworkScope::None);
    bounded.filesystem.posture =
        FilesystemPosture::BoundedRoots(BTreeSet::from([FilesystemRoot::new(
            IntegrityDigest::from_bytes([3; 32]),
            Vec::new(),
        )
        .unwrap()]));
    bounded.filesystem.permissions = BTreeSet::from([FilesystemPermission::Read]);
    bounded.children = ChildDelegationScope::None;
    bounded.containment = ContainmentStrategy::WorkspaceBoundV1;
    bounded.budget.max_operations = Some(1);
    bounded.budget.max_bytes = Some(4096);
    bounded.validate().unwrap();
}

#[test]
fn legacy_unrestricted_broad_scope_keeps_finite_budget_validation() {
    let mut legacy = broad_scope(NetworkScope::BroadSameUser);
    legacy.managed_policy = ManagedPolicyCoverage::Unrestricted {
        policy_digest: IntegrityDigest::from_bytes([42; 32]),
    };
    legacy.budget = EffectBudget {
        max_operations: Some(1),
        max_bytes: Some(4096),
    };
    legacy.validate().unwrap();
    assert!(legacy.digest().is_ok());
}
