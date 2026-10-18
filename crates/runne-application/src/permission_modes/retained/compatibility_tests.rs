use super::{model::*, tests_support::*};
use crate::{
    permission_modes::{FilesystemPermission as Fs, ModeSelection, NetworkScope, PermissionMode},
    project_trust::{ManagedEffectClass, ManagedEffectDecision as D},
};
use runne_api::ApiPrincipalId;
use runne_domain::id::{IntegrityDigest, ProjectId};
use std::collections::BTreeSet;

use crate::{
    permission_modes::{
        CompositeEffectScope, ContainmentStrategy, EffectBudget, FilesystemPosture,
        FilesystemScope, LocalCommandPermissionBindingV1, ManagedPolicyCoverage, PermissionScope,
        RetainedBoundaryObservationV1, RetainedClockObservationV1, RetainedCurrentFactsInputV1,
        RetainedCurrentFactsV1, RetainedExecutionObservationV1, RetainedObservationContextV1,
        RetainedOwnerCoordinatesV1,
    },
    project_trust::{
        ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, ProjectTrustRecord,
        managed_effect_policy_digest_v2,
    },
};

fn before_go() -> RetainedPhaseObservationV1 {
    RetainedPhaseObservationV1 {
        phase: RetainedPhaseV1::BeforeGo,
        runtime_start: None,
        elapsed_runtime_ms: None,
    }
}

#[test]
fn checked_full_policy_compatible_observation_preserves_unresolved_release_requirements() {
    let fixture = Fixture::new();
    let result = crate::permission_modes::PermissionPolicyCompiler::evaluate_retained_v1(
        &fixture.input(before_go()),
    );
    let RetainedPolicyEvaluationV1::PolicyCompatible {
        release_requirements,
        ..
    } = result
    else {
        panic!("a checked broad FullAccess observation should be policy-compatible");
    };
    assert_eq!(
        release_requirements.owner_compatibility,
        RetainedReleaseRequirementStateV1::Unresolved
    );
    assert_eq!(
        release_requirements.native_one_go_lineage,
        RetainedReleaseRequirementStateV1::Unresolved
    );
}

#[test]
fn unused_network_decision_and_revision_do_not_invalidate_network_none_scope() {
    let rights = [Fs::Read, Fs::Create, Fs::Write, Fs::Delete]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut fixture = Fixture::v2(NetworkScope::None, rights);
    let base = full_allow_snapshot();
    let changed = crate::project_trust::ProjectTrustEffectPolicySnapshot {
        record: crate::project_trust::ProjectTrustRecord {
            revision: 8,
            ..base.record
        },
        policy: base
            .policy
            .with_decision(ManagedEffectClass::NetworkUse, D::Deny),
    };
    fixture.replace_current(changed, PermissionMode::FullAccess, 9);
    assert!(matches!(
        crate::permission_modes::PermissionPolicyCompiler::evaluate_retained_v1(
            &fixture.input(before_go())
        ),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
}

#[test]
fn full_access_keeps_known_broad_sensitive_unbounded_held_process_inside_policy() {
    let mut fixture = Fixture::new();
    fixture.resource.workspace = crate::permission_modes::WorkspaceRelation::Outside;
    fixture.resource.sensitivity = crate::permission_modes::Sensitivity::Sensitive;
    fixture.resource.size = crate::permission_modes::SizeBound::Unbounded;
    fixture.resource.resolution = crate::permission_modes::ResolutionState::HeldSafe;
    fixture.resource.resolved_path = Some(
        crate::permission_modes::FilesystemRoot::new(digest(12), vec!["sensitive".into()]).unwrap(),
    );
    assert!(matches!(
        crate::permission_modes::PermissionPolicyCompiler::evaluate_retained_v1(
            &fixture.input(before_go())
        ),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
}

#[test]
fn full_access_does_not_bypass_missing_held_resource_identity() {
    let mut fixture = Fixture::new();
    fixture.resource.resolution = crate::permission_modes::ResolutionState::AmbiguousOrUnheld;
    assert!(!matches!(
        crate::permission_modes::PermissionPolicyCompiler::evaluate_retained_v1(
            &fixture.input(before_go())
        ),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
            | RetainedPolicyEvaluationV1::RequireApproval { .. }
    ));
}

#[test]
fn trust_epoch_and_managed_deny_mask_changes_require_owner_compatibility() {
    for change in 0..2 {
        let mut fixture = Fixture::new();
        let base = full_allow_snapshot();
        let mut record = base.record;
        if change == 0 {
            record.instance_epoch += 1;
        } else {
            record.managed_deny_mask = 1;
        }
        fixture.replace_current(
            crate::project_trust::ProjectTrustEffectPolicySnapshot { record, ..base },
            PermissionMode::FullAccess,
            3,
        );
        assert_eq!(
            crate::permission_modes::PermissionPolicyCompiler::evaluate_retained_v1(
                &fixture.input(before_go())
            ),
            RetainedPolicyEvaluationV1::NotEvaluable(
                RetainedNotEvaluableReasonV1::OwnerCompatibilityRequired
            )
        );
    }
}

#[test]
fn risk_based_process_start_requires_exact_approval_and_managed_deny_wins() {
    let mut fixture = Fixture::new();
    fixture.replace_current(full_allow_snapshot(), PermissionMode::RiskBased, 3);
    assert!(matches!(
        crate::permission_modes::PermissionPolicyCompiler::evaluate_retained_v1(
            &fixture.input(before_go())
        ),
        RetainedPolicyEvaluationV1::RequireApproval { .. }
    ));
    let denied = crate::project_trust::ProjectTrustEffectPolicySnapshot {
        record: fixture.current.snapshot.record,
        policy: fixture
            .current
            .snapshot
            .policy
            .with_decision(ManagedEffectClass::ProcessStart, D::Deny),
    };
    fixture.replace_current(denied, PermissionMode::FullAccess, 4);
    assert_eq!(
        crate::permission_modes::PermissionPolicyCompiler::evaluate_retained_v1(
            &fixture.input(before_go())
        ),
        RetainedPolicyEvaluationV1::Denied
    );
}

pub(super) fn scope(
    permission_scope: PermissionScope,
    project: ProjectTrustProjectId,
    snapshot: ProjectTrustEffectPolicySnapshot,
    containment: ContainmentStrategy,
    network: NetworkScope,
    permissions: BTreeSet<Fs>,
) -> CompositeEffectScope {
    CompositeEffectScope {
        permission_scope,
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BroadSameUser,
            permissions,
        },
        network,
        managed_policy: ManagedPolicyCoverage::from_closed_snapshot(project, &snapshot).unwrap(),
        children: crate::permission_modes::ChildDelegationScope::Unbounded,
        budget: EffectBudget {
            max_operations: None,
            max_bytes: None,
        },
        lifetime_ms: 120_000,
        containment,
        protected_control_plane_policy_digest: super::tests_support::digest(13),
    }
}

pub(super) fn current_facts(
    original: &LocalCommandPermissionBindingV1,
    selection: ModeSelection,
    scope: CompositeEffectScope,
    project_id: ProjectId,
    snapshot: ProjectTrustEffectPolicySnapshot,
    coordinates: RetainedOwnerCoordinatesV1,
) -> RetainedCurrentFactsV1 {
    let project = ProjectTrustProjectId::from_bytes(*project_id.as_bytes());
    let app_policy_digest =
        IntegrityDigest::from_bytes(managed_effect_policy_digest_v2(project, &snapshot).unwrap());
    let candidate = original.approval().clone();
    let observation_context = Some(RetainedObservationContextV1 {
        format_version: 1,
        original_binding_digest: original.digest(),
        authorization_revision: selection.authorization_revision,
        current_snapshot_digest: app_policy_digest,
        native_boundary_owner_id: coordinates.native_boundary_owner_id.clone(),
        native_boundary_owner_epoch: coordinates.native_boundary_owner_epoch,
        boundary: RetainedBoundaryObservationV1::Observed {
            source_policy_version: coordinates.source_policy_version,
            command_policy_version: coordinates.command_policy_version,
            protected_generation: coordinates.protected_generation,
            root_generation: coordinates.root_generation,
        },
    });
    RetainedCurrentFactsV1::checked(RetainedCurrentFactsInputV1 {
        original_binding_digest: original.digest(),
        selection,
        scope,
        project_id,
        snapshot,
        app_policy_digest,
        command: original.command().clone(),
        command_intent_digest: original.command_intent_digest(),
        limits: original.limits(),
        candidate,
        coordinates,
        observation_context,
        execution_observation: RetainedExecutionObservationV1::Active,
        assignment_lease_deadline_unix_ms: 600_000,
        observed_clock: RetainedClockObservationV1 {
            epoch: 50,
            wall_unix_ms: 100_100,
            monotonic_ms: 1_100,
        },
    })
    .unwrap()
}

#[test]
fn independently_observed_current_candidate_must_preserve_original_command_identity() {
    let mut fixture = Fixture::new();
    fixture.current.candidate.target_version += 1;
    assert_eq!(
        crate::permission_modes::PermissionPolicyCompiler::evaluate_retained_v1(
            &fixture.input(before_go())
        ),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::OriginalIdentityMismatch
        )
    );
}

pub(super) fn coordinates(
    original: &LocalCommandPermissionBindingV1,
    trust_record: ProjectTrustRecord,
    principal_id: ApiPrincipalId,
    project_id: ProjectId,
) -> RetainedOwnerCoordinatesV1 {
    RetainedOwnerCoordinatesV1 {
        runtime_authority_id: original
            .scope()
            .permission_scope
            .runtime_authority_id
            .0
            .clone(),
        principal_id,
        workspace_id: original.scope().permission_scope.workspace_id,
        project_id,
        project_version: original.project_version(),
        workspace_version: original.workspace_version(),
        admitted_root_version: original.admitted_root_version(),
        held_root_identity_digest: original.held_root_identity_digest(),
        assignment: original.assignment().clone(),
        claim_stream_version: original.claim_stream_version(),
        invocation_id: original.invocation_id(),
        root_generation: 6,
        protected_generation: 7,
        native_boundary_owner_id: "native-owner-a".into(),
        native_boundary_owner_epoch: 8,
        protected_policy_digest: original.scope().protected_control_plane_policy_digest,
        source_policy_version: 2,
        command_policy_version: 1,
        trust_record,
    }
}
