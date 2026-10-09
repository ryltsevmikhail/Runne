use super::{model::*, tests_support::Fixture};
use crate::{
    permission_modes::{
        FilesystemPermission as Fs, FilesystemRoot, ManagedPolicyCoverage, NetworkScope,
        PermissionMode, PermissionPolicyCompiler, RetainedHumanEvidenceV1,
    },
    project_trust::{
        ManagedEffectClass, ManagedEffectDecision as D, ProjectTrustEffectPolicySnapshot,
        ProjectTrustProjectId, managed_effect_policy_digest_v2,
    },
};
use runne_domain::id::{IntegrityDigest, ProjectId};
use std::collections::BTreeSet;

fn before_go() -> RetainedPhaseObservationV1 {
    RetainedPhaseObservationV1 {
        phase: RetainedPhaseV1::BeforeGo,
        runtime_start: None,
        elapsed_runtime_ms: None,
    }
}

fn running(fixture: &Fixture) -> RetainedPhaseObservationV1 {
    RetainedPhaseObservationV1 {
        phase: RetainedPhaseV1::Running,
        runtime_start: Some(RetainedRuntimeStartV1 {
            original_binding_digest: fixture.original.digest(),
            invocation_id: fixture.original.invocation_id(),
            clock_epoch: 50,
            monotonic_start_ms: 1_050,
            wall_start_unix_ms: 100_050,
        }),
        elapsed_runtime_ms: Some(50),
    }
}

fn evidence_for(
    mut input: crate::permission_modes::RetainedHumanEvidenceInputV1,
    project_id: ProjectId,
    snapshot: ProjectTrustEffectPolicySnapshot,
) -> crate::permission_modes::RetainedHumanEvidenceInputV1 {
    let project = ProjectTrustProjectId::from_bytes(*project_id.as_bytes());
    let coverage = ManagedPolicyCoverage::from_closed_snapshot(project, &snapshot).unwrap();
    input.scope.managed_policy = coverage;
    input.snapshot = snapshot;
    input.project_id = project_id;
    input.app_policy_digest =
        IntegrityDigest::from_bytes(managed_effect_policy_digest_v2(project, &snapshot).unwrap());
    input.binding.composite_scope_digest = input.scope.digest().unwrap();
    input.binding.relevant_policy_digest = coverage.policy_digest();
    input.binding_digest = input.binding.digest();
    let provided = super::provided_classes::retained_provided_classes(&input.scope).unwrap();
    input.relevant_semantics_digest =
        super::semantics::retained_relevant_semantics(&snapshot, provided, 1, 2, 1)
            .unwrap()
            .digest;
    input
}

#[test]
fn frozen_candidate_survives_full_snapshot_digest_change_and_never_gets_restamped() {
    let rights = [Fs::Read, Fs::Create, Fs::Write, Fs::Delete]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut fixture = Fixture::v2(NetworkScope::None, rights);
    let original_candidate = fixture.original.approval().clone();
    let base = fixture.current.snapshot;
    let changed = ProjectTrustEffectPolicySnapshot {
        record: crate::project_trust::ProjectTrustRecord {
            revision: base.record.revision + 1,
            ..base.record
        },
        policy: base
            .policy
            .with_decision(ManagedEffectClass::NetworkUse, D::Deny),
    };
    fixture.replace_current(changed, PermissionMode::FullAccess, 3);
    assert_ne!(
        fixture.current.app_policy_digest,
        fixture.original.closed_rules_digest()
    );
    assert_eq!(fixture.current.candidate, original_candidate);
    assert!(matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
    for digest in [
        fixture.current.scope.managed_policy.policy_digest(),
        super::tests_support::digest(99),
    ] {
        let mut changed_candidate = Fixture::v2(
            NetworkScope::None,
            [Fs::Read, Fs::Create, Fs::Write, Fs::Delete]
                .into_iter()
                .collect(),
        );
        changed_candidate.replace_current(changed, PermissionMode::FullAccess, 3);
        changed_candidate.current.candidate.relevant_policy_digest = digest;
        assert_eq!(
            PermissionPolicyCompiler::evaluate_retained_v1(&changed_candidate.input(before_go())),
            RetainedPolicyEvaluationV1::NotEvaluable(
                RetainedNotEvaluableReasonV1::OriginalIdentityMismatch
            )
        );
    }
}

#[test]
fn other_original_and_future_dated_humans_are_rejected_even_when_current_auto_admits() {
    let fixture = Fixture::new();
    let other = Fixture::distinct();
    let proof = RetainedHumanEvidenceV1::checked(
        &other.original,
        &other.context,
        other.human_evidence_input(600_000),
    )
    .unwrap();
    for selected in [false, true] {
        let mut input = fixture.input(before_go());
        if selected {
            input.selected_human_candidate = Some(&proof);
        } else {
            input.admission = RetainedAdmissionEvidenceV1::Human(&proof);
        }
        assert_eq!(
            PermissionPolicyCompiler::evaluate_retained_v1(&input),
            RetainedPolicyEvaluationV1::NotEvaluable(
                RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent
            )
        );
    }
    let future = fixture.current_human_evidence(600_000, 100_101);
    let mut input = fixture.input(before_go());
    input.selected_human_candidate = Some(&future);
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&input),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent
        )
    );
}

#[test]
fn proof_cannot_change_project_or_trust_owner_coordinates() {
    let fixture = Fixture::new();
    let base = fixture.human_evidence_input(600_000);
    let mut bytes = [0; 16];
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    bytes[15] = 99;
    let other_project = ProjectId::from_bytes(bytes);
    let project_proof = evidence_for(base.clone(), other_project, base.snapshot);
    assert!(
        RetainedHumanEvidenceV1::checked(
            &fixture.original,
            &fixture.context,
            project_proof.clone(),
        )
        .is_err()
    );
    for changed_owner in 0..3 {
        let mut snapshot = base.snapshot;
        match changed_owner {
            0 => snapshot.record.instance_epoch += 1,
            1 => snapshot.record.status = crate::project_trust::ProjectTrustStatus::Trusted,
            _ => snapshot.record.managed_deny_mask = 1,
        }
        let input = evidence_for(base.clone(), fixture.original.project_id(), snapshot);
        assert!(
            RetainedHumanEvidenceV1::checked(&fixture.original, &fixture.context, input,).is_err()
        );
    }
}

#[test]
fn equal_aggregate_ask_does_not_reuse_a_proof_for_a_different_class() {
    let mut fixture = Fixture::new();
    let base = fixture.current.snapshot;
    let read_ask = ProjectTrustEffectPolicySnapshot {
        policy: base
            .policy
            .with_decision(ManagedEffectClass::FsRead, D::Ask),
        ..base
    };
    fixture.replace_current(read_ask, PermissionMode::FullAccess, 3);
    let proof = fixture.current_human_evidence(600_000, 100_050);
    let network_ask = ProjectTrustEffectPolicySnapshot {
        policy: base
            .policy
            .with_decision(ManagedEffectClass::NetworkUse, D::Ask),
        ..base
    };
    fixture.replace_current(network_ask, PermissionMode::FullAccess, 4);
    let mut input = fixture.input(before_go());
    input.selected_human_candidate = Some(&proof);
    assert!(matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&input),
        RetainedPolicyEvaluationV1::RequireApproval { .. }
    ));
}

#[test]
fn selected_human_must_be_accepted_before_running_start() {
    let mut fixture = Fixture::new();
    let base = fixture.current.snapshot;
    let ask = ProjectTrustEffectPolicySnapshot {
        policy: base
            .policy
            .with_decision(ManagedEffectClass::ProcessStart, D::Ask),
        ..base
    };
    fixture.replace_current(ask, PermissionMode::FullAccess, 3);
    let early = fixture.current_human_evidence(600_000, 100_049);
    let mut input = fixture.input(running(&fixture));
    input.selected_human_candidate = Some(&early);
    assert!(matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&input),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
    let late = fixture.current_human_evidence(600_000, 100_051);
    input.selected_human_candidate = Some(&late);
    assert!(matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&input),
        RetainedPolicyEvaluationV1::StopRequired { .. }
    ));
}

#[test]
fn oversized_current_owner_string_and_resource_path_fail_before_evaluation() {
    let mut current = Fixture::new();
    current.current.coordinates.runtime_authority_id = "x".repeat(257);
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&current.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::CurrentFactsInconsistent
        )
    );
    let mut resource = Fixture::new();
    resource.resource.resolved_path = Some(FilesystemRoot {
        root_identity: super::tests_support::digest(12),
        components: vec!["x".into(); 257],
    });
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&resource.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::CurrentFactsInconsistent
        )
    );
}
