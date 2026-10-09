use super::{model::*, tests_support::*};
use crate::{
    permission_modes::{
        PermissionMode, PermissionPolicyCompiler, RetainedBoundaryObservationV1,
        RetainedBoundaryUnavailableReasonV1, RetainedExecutionObservationV1,
        RetainedHumanEvidenceInputV1, RetainedHumanEvidenceV1,
    },
    project_trust::{
        ManagedEffectClass, ManagedEffectDecision as D, ProjectTrustProjectId,
        managed_effect_policy_digest_v2,
    },
};
use runne_domain::id::{ApprovalId, IntegrityDigest};

impl Fixture {
    fn human_evidence(&self) -> RetainedHumanEvidenceV1 {
        RetainedHumanEvidenceV1::checked(
            &self.original,
            &self.context,
            self.human_evidence_input(700_000),
        )
        .unwrap()
    }

    pub(super) fn human_evidence_input(&self, expiry: i64) -> RetainedHumanEvidenceInputV1 {
        self.human_input_for(
            self.original.scope().clone(),
            self.original.closed_rules_snapshot(),
            expiry,
            90_000,
        )
    }

    pub(super) fn current_human_evidence(
        &self,
        expiry: i64,
        accepted_at: i64,
    ) -> RetainedHumanEvidenceV1 {
        let input = self.human_input_for(
            self.current.scope.clone(),
            self.current.snapshot,
            expiry,
            accepted_at,
        );
        RetainedHumanEvidenceV1::checked(&self.original, &self.context, input).unwrap()
    }

    pub(super) fn human_input_for(
        &self,
        scope: crate::permission_modes::CompositeEffectScope,
        snapshot: crate::project_trust::ProjectTrustEffectPolicySnapshot,
        expiry: i64,
        accepted_at: i64,
    ) -> RetainedHumanEvidenceInputV1 {
        let project = ProjectTrustProjectId::from_bytes(*self.original.project_id().as_bytes());
        let app_digest = IntegrityDigest::from_bytes(
            managed_effect_policy_digest_v2(project, &snapshot).unwrap(),
        );
        let provided = super::provided_classes::retained_provided_classes(&scope).unwrap();
        let semantics =
            super::semantics::retained_relevant_semantics(&snapshot, provided, 1, 2, 1).unwrap();
        let mut binding = self.candidate.clone();
        binding.composite_scope_digest = scope.digest().unwrap();
        binding.relevant_policy_digest = scope.managed_policy.policy_digest();
        RetainedHumanEvidenceInputV1 {
            approval_id: ApprovalId::from_bytes([
                0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 6,
            ]),
            original_binding_digest: self.original.digest(),
            binding_digest: binding.digest(),
            binding,
            scope,
            snapshot,
            project_id: self.original.project_id(),
            app_policy_digest: app_digest,
            evaluator_version: 1,
            semantics_version: 1,
            preset_version: 1,
            source_policy_version: 2,
            command_policy_version: 1,
            relevant_semantics_digest: semantics.digest,
            accepted_by: self.candidate.principal_id.clone(),
            accepted_at_unix_ms: accepted_at,
            expires_at_unix_ms: expiry,
        }
    }
}

fn before_go() -> RetainedPhaseObservationV1 {
    RetainedPhaseObservationV1 {
        phase: RetainedPhaseV1::BeforeGo,
        runtime_start: None,
        elapsed_runtime_ms: None,
    }
}

#[test]
fn current_auto_does_not_need_a_well_formed_but_expired_historical_human_proof() {
    let fixture = Fixture::new();
    let human = crate::permission_modes::RetainedHumanEvidenceV1::checked(
        &fixture.original,
        &fixture.context,
        fixture.human_evidence_input(100_050),
    )
    .unwrap();
    let mut input = fixture.input(before_go());
    input.admission = RetainedAdmissionEvidenceV1::Human(&human);
    assert!(matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&input),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
}

#[test]
fn malformed_human_data_cannot_be_ignored_by_a_current_auto_preset() {
    let fixture = Fixture::new();
    let mut human = fixture.human_evidence_input(600_000);
    human.app_policy_digest = digest(99);
    assert!(
        crate::permission_modes::RetainedHumanEvidenceV1::checked(
            &fixture.original,
            &fixture.context,
            human
        )
        .is_err()
    );
}

#[test]
fn new_current_ask_requires_its_exact_human_envelope_before_go() {
    let mut fixture = Fixture::new();
    let base = full_allow_snapshot();
    let current = crate::project_trust::ProjectTrustEffectPolicySnapshot {
        policy: base
            .policy
            .with_decision(ManagedEffectClass::ProcessStart, D::Ask),
        ..base
    };
    fixture.replace_current(current, PermissionMode::FullAccess, 3);
    let human = fixture.current_human_evidence(600_000, 100_050);
    let mut input = fixture.input(before_go());
    input.selected_human_candidate = Some(&human);
    assert!(matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&input),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
}

#[test]
fn proof_cannot_extend_original_lifetime_or_widen_non_policy_scope() {
    let fixture = Fixture::new();
    let mut longer = fixture.human_evidence_input(700_001);
    assert!(
        crate::permission_modes::RetainedHumanEvidenceV1::checked(
            &fixture.original,
            &fixture.context,
            longer.clone()
        )
        .is_err()
    );
    longer = fixture.human_evidence_input(600_000);
    longer.scope.children = crate::permission_modes::ChildDelegationScope::MaxDepth(2);
    longer.binding.composite_scope_digest = longer.scope.digest().unwrap();
    longer.binding_digest = longer.binding.digest();
    assert!(
        crate::permission_modes::RetainedHumanEvidenceV1::checked(
            &fixture.original,
            &fixture.context,
            longer
        )
        .is_err()
    );
}

#[test]
fn original_human_admission_is_never_synthesized_from_auto() {
    let fixture = Fixture::new();
    let input = fixture.input(before_go());
    assert_eq!(input.admission, RetainedAdmissionEvidenceV1::Auto);
    assert!(
        fixture.human_evidence().expires_at_unix_ms()
            <= fixture.original.approval().expires_at_unix_ms
    );
}

#[test]
fn pending_admission_and_nonactive_execution_never_become_retained_grants() {
    let fixture = Fixture::new();
    let mut input = fixture.input(before_go());
    input.admission = RetainedAdmissionEvidenceV1::Pending;
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&input),
        RetainedPolicyEvaluationV1::NotEvaluable(RetainedNotEvaluableReasonV1::MissingAdmission)
    );
    for state in [
        RetainedExecutionObservationV1::Cancelled,
        RetainedExecutionObservationV1::Revoked,
        RetainedExecutionObservationV1::TerminalCommitted,
    ] {
        let mut fixture = Fixture::new();
        fixture.current.execution_observation = state;
        assert_eq!(
            PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
            RetainedPolicyEvaluationV1::NotEvaluable(
                RetainedNotEvaluableReasonV1::ExecutionNotActive
            )
        );
    }
    let mut unavailable = Fixture::new();
    unavailable.current.execution_observation = RetainedExecutionObservationV1::Unavailable;
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&unavailable.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::ExecutionUnavailable
        )
    );
}

#[test]
fn missing_or_unavailable_owner_observations_and_expired_assignment_lease_fail_closed() {
    let mut missing = Fixture::new();
    missing.current.observation_context = None;
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&missing.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::MissingCurrentObservation
        )
    );
    let mut unavailable = Fixture::new();
    unavailable
        .current
        .observation_context
        .as_mut()
        .unwrap()
        .boundary = RetainedBoundaryObservationV1::Unavailable(
        RetainedBoundaryUnavailableReasonV1::MissingOwner,
    );
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&unavailable.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::OwnerCompatibilityRequired
        )
    );
    let mut unknown_version = Fixture::new();
    unknown_version
        .current
        .observation_context
        .as_mut()
        .unwrap()
        .format_version = 2;
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&unknown_version.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(RetainedNotEvaluableReasonV1::UnsupportedVersion)
    );
    let mut expired_lease = Fixture::new();
    expired_lease.current.assignment_lease_deadline_unix_ms =
        expired_lease.current.observed_clock.wall_unix_ms;
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&expired_lease.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::AssignmentLeaseExpired
        )
    );
}

#[test]
fn current_observation_and_human_envelope_must_link_to_the_exact_original_digest() {
    let mut fixture = Fixture::new();
    fixture.current.original_binding_digest = digest(88);
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::CurrentFactsInconsistent
        )
    );
    let mut proof = fixture.human_evidence_input(600_000);
    proof.original_binding_digest = digest(89);
    assert!(RetainedHumanEvidenceV1::checked(&fixture.original, &fixture.context, proof).is_err());
}
