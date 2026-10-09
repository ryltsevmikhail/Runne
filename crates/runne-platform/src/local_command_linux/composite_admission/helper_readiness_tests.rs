use super::*;
use runne_api::ApiPrincipalId;
use runne_application::{
    permission_modes::{FilesystemScope, ManagedPolicyCoverage, PermissionScope},
    ports::RuntimeAuthorityId,
    project_trust::{
        ManagedEffectDecision, ManagedEffectPolicyV1, ProjectTrustEffectPolicySnapshot,
        ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus,
    },
};
use runne_domain::id::WorkspaceId;
use std::collections::BTreeSet;

fn digest(byte: u8) -> IntegrityDigest {
    IntegrityDigest::from_bytes([byte; 32])
}

fn scope() -> CompositeEffectScope {
    let snapshot = ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Managed,
            instance_epoch: 7,
            revision: 9,
            managed_deny_mask: 0,
        },
        policy: ManagedEffectPolicyV1::new(1, [ManagedEffectDecision::Allow; 6]),
    };
    CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: RuntimeAuthorityId("readiness-test".into()),
            principal_id: ApiPrincipalId::new("user:readiness-test").unwrap(),
            workspace_id: WorkspaceId::from_bytes([1; 16]),
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
        network: NetworkScope::BroadSameUser,
        managed_policy: ManagedPolicyCoverage::from_closed_snapshot(
            ProjectTrustProjectId::from_bytes([2; 16]),
            &snapshot,
        )
        .unwrap(),
        children: ChildDelegationScope::Unbounded,
        budget: EffectBudget {
            max_operations: None,
            max_bytes: None,
        },
        lifetime_ms: 120_000,
        containment: ContainmentStrategy::SameUserCompositeV1,
        protected_control_plane_policy_digest: digest(3),
    }
}

#[test]
fn full_access_mapping_changes_only_the_protected_identity_and_binds_readiness() {
    let original = scope();
    let canonical = translate_full_access_scope(&original, digest(3), digest(4)).unwrap();
    let mut expected = original.clone();
    expected.protected_control_plane_policy_digest = digest(4);
    assert_eq!(canonical, expected);

    let original_digest = original.digest().unwrap();
    let canonical_digest = canonical.digest().unwrap();
    let handle = readiness_handle(
        original_digest.as_bytes(),
        canonical_digest.as_bytes(),
        digest(5),
    )
    .unwrap();
    assert_ne!(handle, digest(0));
    assert_ne!(handle, digest(5));
    assert_ne!(
        handle,
        readiness_handle(
            original_digest.as_bytes(),
            canonical_digest.as_bytes(),
            digest(6),
        )
        .unwrap()
    );
}

#[test]
fn full_access_mapping_rejects_owner_and_shape_mismatches() {
    let original = scope();
    assert!(translate_full_access_scope(&original, digest(8), digest(4)).is_none());

    let mut candidates = Vec::new();
    let mut finite = original.clone();
    finite.budget.max_operations = Some(1);
    candidates.push(finite);
    let mut wrong_network = original.clone();
    wrong_network.network = NetworkScope::None;
    candidates.push(wrong_network);
    let mut wrong_containment = original.clone();
    wrong_containment.containment = ContainmentStrategy::SameUserCompositeV2;
    candidates.push(wrong_containment);
    let mut wrong_rights = original.clone();
    wrong_rights
        .filesystem
        .permissions
        .remove(&FilesystemPermission::Delete);
    candidates.push(wrong_rights);
    let mut nonclosed = original.clone();
    nonclosed.managed_policy = ManagedPolicyCoverage::Unrestricted {
        policy_digest: digest(9),
    };
    candidates.push(nonclosed);
    let mut v2_labeled = original.clone();
    v2_labeled.protected_control_plane_policy_digest = digest(4);
    candidates.push(v2_labeled);
    let mut expired_shape = original.clone();
    expired_shape.lifetime_ms = MAX_SCOPE_LIFETIME_MS + 1;
    candidates.push(expired_shape);

    assert!(
        candidates
            .iter()
            .all(
                |candidate| translate_full_access_scope(candidate, digest(3), digest(4)).is_none()
            )
    );
}
