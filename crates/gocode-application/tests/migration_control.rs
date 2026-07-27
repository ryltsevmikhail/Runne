use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use gocode_application::migration::{
    error::MigrationError,
    gates::{
        GateContext, GateEvidence, GateRevocationReason, GateStatus, MigrationEvidence,
        PhaseGatePolicy,
    },
    manifests::{
        ArtifactRef, ArtifactValidation, CandidateValidationReport, DrainReportArtifact,
        ImportDisposition, MigrationCounts, MigrationReport, MigrationReportFields,
        RetirementManifest, RollbackPolicy,
    },
    ports::{
        LoadedMigrationPlan, MigrationCommandContext, MigrationCommandFingerprint, MigrationCommit,
        MigrationCommitResult, MigrationControlStore, MigrationMutation, MigrationReceipt,
        MigrationReceiptLookup, MigrationStoreError, SanitizedShadowInput, ShadowDiffReport,
        ShadowExecutionError, ShadowExecutionPort,
    },
    rollout::{
        CanaryPolicy, CutoverPolicy, LegacyReferenceDisposition, LegacyReferenceInventory,
        LegacyReferenceSet, PreDispatchFallbackPolicy, RetirementReadiness, RetirementRequirement,
        RolloutStep,
    },
    service::{
        BeginDrainInput, CommitCutoverInput, CutoverIntent, EmergencyRevokeInput, MigrationService,
        PrepareCutoverInput, RecordEvidenceInput, RetireSourceInput, StagePlanInput,
        StartRollbackInput,
    },
    state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
    types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        FencingToken, GateFamily, GateId, GatePolicyRef, MigrationCycleId, MigrationPlanId,
        OperatorId, RollbackDisposition, RoutingGeneration, RoutingSnapshot, RoutingUnit,
        RuntimeAuthority, RuntimeGenerationRef,
    },
};
use gocode_domain::{
    id::{CommandId, IdempotencyKey},
    timestamp::Timestamp,
};

#[test]
fn stage_plan_is_idempotent_and_source_only() {
    let store = MemoryMigrationStore::default();
    let service = MigrationService::new(store.clone(), PureShadow);

    let first = service.stage_plan(stage_context(), stage_input()).unwrap();
    let retry = service.stage_plan(stage_context(), stage_input()).unwrap();

    assert_eq!(first, retry);
    assert!(matches!(
        first.snapshot.authority,
        RuntimeAuthority::Source(_)
    ));
    assert_eq!(store.transition_count(), 1);
}

#[test]
fn stage_plan_rejects_same_command_with_a_different_candidate() {
    let store = MemoryMigrationStore::default();
    let service = MigrationService::new(store.clone(), PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();

    let replacement = RuntimeGenerationRef::new("runtime-native-replacement").unwrap();
    let mut conflicting = stage_input();
    conflicting.plan.candidate = replacement.clone();
    conflicting.initial_snapshot = RoutingSnapshot::new(
        RoutingGeneration::new(1).unwrap(),
        source_generation(),
        replacement,
        MigrationPhase::Baseline,
        RuntimeAuthority::Source(source_generation()),
        routing_unit(),
        FencingToken::new([7; 32]).unwrap(),
        RollbackDisposition::Eligible,
        Timestamp::from_unix_micros(1),
    )
    .unwrap();

    assert_eq!(
        service.stage_plan(stage_context(), conflicting),
        Err(MigrationError::StorageContractViolation)
    );
    assert_eq!(store.transition_count(), 1);
}

#[test]
fn phases_zero_through_three_never_select_candidate() {
    let (service, _) = seeded_service();

    for target in [
        MigrationPhase::Foundation,
        MigrationPhase::ReadOnlyParity,
        MigrationPhase::SimulatedShadow,
    ] {
        service
            .record_evidence(
                next_context(&service),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        service
            .advance_phase(next_context(&service), plan_id(), target)
            .unwrap();

        let head = service.routing_head(&routing_unit()).unwrap().unwrap();
        assert!(matches!(head.authority, RuntimeAuthority::Source(_)));
    }
}

#[test]
fn advance_phase_rejects_non_adjacent_target_before_evidence_lookup() {
    let (service, _) = seeded_service();

    assert_eq!(
        service.advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::SimulatedShadow,
        ),
        Err(MigrationError::InvalidPhaseTransition {
            from: MigrationPhase::Baseline,
            to: MigrationPhase::SimulatedShadow,
        })
    );
}

#[test]
fn record_evidence_rejects_same_command_with_changed_semantics() {
    let (service, store) = seeded_service();
    let context = next_context(&service);
    service
        .record_evidence(
            context.clone(),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::Baseline {
                    source_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".to_owned(),
                    inventory_digest: ArtifactDigest::from_bytes([8; 32]),
                    fixture_digest: ArtifactDigest::from_bytes([9; 32]),
                },
            },
        )
        .unwrap();

    assert_eq!(
        service.record_evidence(
            context,
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::Baseline {
                    source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                    inventory_digest: ArtifactDigest::from_bytes([8; 32]),
                    fixture_digest: ArtifactDigest::from_bytes([9; 32]),
                },
            },
        ),
        Err(MigrationError::StorageContractViolation)
    );
    assert_eq!(store.evidence_count(), 1);
}

#[test]
fn record_evidence_rejects_scope_mismatch_without_mutation() {
    let (service, store) = seeded_service();

    assert_eq!(
        service.record_evidence(
            next_context(&service),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::Foundation {
                    contract_digest: ArtifactDigest::from_bytes([99; 32]),
                    store_integrity_digest: ArtifactDigest::from_bytes([10; 32]),
                    deterministic_test_digest: ArtifactDigest::from_bytes([11; 32]),
                },
            },
        ),
        Err(MigrationError::EvidenceScopeMismatch)
    );
    assert_eq!(store.evidence_count(), 0);
}

#[test]
fn internal_canary_requires_every_critical_family() {
    let (service, _) = shadow_ready_service();
    record_phase4_evidence_except(&service, Some(GateFamily::CanonicalAudit));
    let before = service.load_plan(&plan_id()).unwrap();

    assert_eq!(
        service.advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::InternalCanary,
        ),
        Err(MigrationError::GateMissing {
            family: GateFamily::CanonicalAudit,
        })
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before);
}

#[test]
fn stale_evidence_blocks_internal_canary_without_mutation() {
    let (service, _) = shadow_ready_service();
    record_phase4_evidence_except(&service, Some(GateFamily::CanonicalAudit));
    let mut expired = phase4_gate_evidence(GateFamily::CanonicalAudit, GateStatus::Passed, 99);
    expired.valid_until = Timestamp::from_unix_micros(100);
    service
        .record_evidence(
            next_context(&service),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::ProductionGate(expired),
            },
        )
        .unwrap();
    let before_plan = service.load_plan(&plan_id()).unwrap();
    let before_head = service.routing_head(&routing_unit()).unwrap();

    assert_eq!(
        service.advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::InternalCanary,
        ),
        Err(MigrationError::GateExpired {
            family: GateFamily::CanonicalAudit,
        })
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before_plan);
    assert_eq!(service.routing_head(&routing_unit()).unwrap(), before_head);
}

#[test]
fn complete_phase4_gate_set_permits_internal_canary_eligibility() {
    let (service, store) = shadow_ready_service();
    record_phase4_evidence_except(&service, None);
    let unrelated_unit = unrelated_routing_unit();
    let unrelated_snapshot = unrelated_source_snapshot();
    store.insert_routing_head(&unrelated_unit, unrelated_snapshot.clone());

    let output = service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::InternalCanary,
        )
        .unwrap();

    assert_eq!(output.plan.phase, MigrationPhase::InternalCanary);
    assert!(matches!(
        service
            .routing_head(&routing_unit())
            .unwrap()
            .unwrap()
            .authority,
        RuntimeAuthority::Source(_)
    ));
    let evidence_set_digest = current_phase4_gate_set_digest(&service);
    let prepared = service
        .prepare_cutover(
            next_routing_context(&service),
            prepare_cutover_input(evidence_set_digest, 10),
        )
        .unwrap();
    let before_mismatched_high_water = service.load_plan(&plan_id()).unwrap();
    let before_mismatched_head = service.routing_head(&routing_unit()).unwrap();
    assert_eq!(
        service.commit_cutover(
            next_routing_context(&service),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id.clone(),
                observed_source_high_water: 11,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        ),
        Err(MigrationError::StorageContractViolation)
    );
    assert_eq!(
        service.load_plan(&plan_id()).unwrap(),
        before_mismatched_high_water
    );
    assert_eq!(
        service.routing_head(&routing_unit()).unwrap(),
        before_mismatched_head
    );
    let committed = service
        .commit_cutover(
            next_routing_context(&service),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 10,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        )
        .unwrap();
    let snapshot = committed.outcome.routing_snapshot.unwrap();
    assert!(matches!(
        snapshot.authority,
        RuntimeAuthority::Candidate(ref generation) if generation == &candidate_generation()
    ));
    assert_eq!(snapshot.cohort, routing_unit().cohort);
    assert_eq!(snapshot.routing_generation.get(), 2);
    assert_eq!(
        service.routing_head(&unrelated_unit).unwrap(),
        Some(unrelated_snapshot)
    );
}

#[test]
fn revocation_between_prepare_and_commit_blocks_cutover() {
    let (service, _) = shadow_ready_service();
    record_phase4_evidence_except(&service, None);
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::InternalCanary,
        )
        .unwrap();
    let evidence_set_digest = current_phase4_gate_set_digest(&service);
    let prepared = service
        .prepare_cutover(
            next_routing_context(&service),
            prepare_cutover_input(evidence_set_digest, 10),
        )
        .unwrap();
    service
        .record_evidence(
            next_context(&service),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::ProductionGate(phase4_gate_evidence(
                    GateFamily::CanonicalAudit,
                    GateStatus::Revoked {
                        reason: GateRevocationReason::SecurityRevoked,
                    },
                    99,
                )),
            },
        )
        .unwrap();
    let before_plan = service.load_plan(&plan_id()).unwrap();
    let before_head = service.routing_head(&routing_unit()).unwrap();

    assert_eq!(
        service.commit_cutover(
            next_routing_context(&service),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 10,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        ),
        Err(MigrationError::GateRevoked {
            family: GateFamily::CanonicalAudit,
        })
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before_plan);
    assert_eq!(service.routing_head(&routing_unit()).unwrap(), before_head);
}

#[test]
fn cohort_expansion_requires_complete_observation_and_resolved_effects() {
    let (service, _) = canary_active_service();
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::CohortRollout,
        )
        .unwrap();
    let evidence_set_digest = current_gate_set_digest(&service, MigrationPhase::CohortRollout);
    let before = service.load_plan(&plan_id()).unwrap();

    assert_eq!(
        service.prepare_cutover(
            next_routing_generation_context(&service, 2),
            prepare_cohort_expansion_input(
                evidence_set_digest,
                20,
                RolloutStep::new(
                    RoutingGeneration::new(2).unwrap(),
                    routing_unit().cohort,
                    2_048,
                    Duration::from_micros(50),
                    Timestamp::from_unix_micros(51),
                    Timestamp::from_unix_micros(101),
                    GatePolicyRef::new("policy-v1").unwrap(),
                )
                .unwrap(),
                0,
                50,
            ),
        ),
        Err(MigrationError::ObservationWindowIncomplete)
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before);

    let mut rollback_unavailable = prepare_cohort_expansion_input(
        evidence_set_digest,
        20,
        valid_rollout_step(2, 2_048),
        0,
        59,
    );
    rollback_unavailable.rollback_policy = RollbackPolicy::ManualOnly;
    assert_eq!(
        service.prepare_cutover(
            next_routing_generation_context(&service, 2),
            rollback_unavailable,
        ),
        Err(MigrationError::RollbackIneligible)
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before);

    assert_eq!(
        service.prepare_cutover(
            next_routing_generation_context(&service, 2),
            prepare_cohort_expansion_input(
                evidence_set_digest,
                20,
                valid_rollout_step(2, 2_048),
                1,
                60,
            ),
        ),
        Err(MigrationError::UnresolvedEffect)
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before);
}

#[test]
fn each_cohort_expansion_allocates_exactly_one_new_generation() {
    let (service, _) = canary_active_service();
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::CohortRollout,
        )
        .unwrap();
    let evidence_set_digest = current_gate_set_digest(&service, MigrationPhase::CohortRollout);

    let first_prepared = service
        .prepare_cutover(
            next_routing_generation_context(&service, 2),
            prepare_cohort_expansion_input(
                evidence_set_digest,
                20,
                valid_rollout_step(2, 2_048),
                0,
                60,
            ),
        )
        .unwrap();
    let first = service
        .commit_cutover(
            next_routing_generation_context(&service, 2),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: first_prepared.outcome.transition_id,
                observed_source_high_water: 20,
                candidate_fencing_token: FencingToken::new([10; 32]).unwrap(),
            },
        )
        .unwrap()
        .outcome
        .routing_snapshot
        .unwrap();

    let before_non_expanding_step = service.load_plan(&plan_id()).unwrap();
    assert_eq!(
        service.prepare_cutover(
            next_routing_generation_context(&service, 3),
            prepare_cohort_expansion_input(
                evidence_set_digest,
                21,
                valid_rollout_step(3, 2_048),
                0,
                65,
            ),
        ),
        Err(MigrationError::ProductionGatesUnavailable)
    );
    assert_eq!(
        service.load_plan(&plan_id()).unwrap(),
        before_non_expanding_step
    );

    let second_prepared = service
        .prepare_cutover(
            next_routing_generation_context(&service, 3),
            prepare_cohort_expansion_input(
                evidence_set_digest,
                21,
                valid_rollout_step(3, 4_096),
                0,
                70,
            ),
        )
        .unwrap();
    let second = service
        .commit_cutover(
            next_routing_generation_context(&service, 3),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: second_prepared.outcome.transition_id,
                observed_source_high_water: 21,
                candidate_fencing_token: FencingToken::new([11; 32]).unwrap(),
            },
        )
        .unwrap()
        .outcome
        .routing_snapshot
        .unwrap();

    assert_eq!(first.routing_generation.get(), 3);
    assert_eq!(
        second.routing_generation.get(),
        first.routing_generation.get() + 1
    );
}

#[test]
fn default_native_preserves_candidate_authority_and_exact_fallback_profile() {
    let (service, _) = canary_active_service();
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::CohortRollout,
        )
        .unwrap();
    let cohort_evidence = current_gate_set_digest(&service, MigrationPhase::CohortRollout);
    let cohort_prepared = service
        .prepare_cutover(
            next_routing_generation_context(&service, 2),
            prepare_cohort_expansion_input(
                cohort_evidence,
                20,
                valid_rollout_step(2, 2_048),
                0,
                80,
            ),
        )
        .unwrap();
    service
        .commit_cutover(
            next_routing_generation_context(&service, 2),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: cohort_prepared.outcome.transition_id,
                observed_source_high_water: 20,
                candidate_fencing_token: FencingToken::new([10; 32]).unwrap(),
            },
        )
        .unwrap();
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::DefaultNative,
        )
        .unwrap();

    let evidence_set_digest = current_gate_set_digest(&service, MigrationPhase::DefaultNative);
    let mut input = prepare_cohort_expansion_input(
        evidence_set_digest,
        30,
        valid_rollout_step(3, 4_096),
        0,
        90,
    );
    input.intent = CutoverIntent::DefaultNative;
    input.rollout_policy =
        CutoverPolicy::DefaultNative(PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
            source_profile: routing_unit().feature_profile,
        });
    let prepared = service
        .prepare_cutover(next_routing_generation_context(&service, 3), input)
        .unwrap();
    let snapshot = service
        .commit_cutover(
            next_routing_generation_context(&service, 3),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 30,
                candidate_fencing_token: FencingToken::new([11; 32]).unwrap(),
            },
        )
        .unwrap()
        .outcome
        .routing_snapshot
        .unwrap();

    assert_eq!(snapshot.routing_generation.get(), 4);
    assert!(matches!(
        snapshot.authority,
        RuntimeAuthority::Candidate(ref generation) if generation == &candidate_generation()
    ));
}

#[test]
fn production_control_primitives_fail_closed_without_mutation() {
    let (service, _) = seeded_service();
    let before_plan = service.load_plan(&plan_id()).unwrap();
    let before_head = service.routing_head(&routing_unit()).unwrap();

    assert_eq!(
        service.prepare_cutover(
            command_context(0, None, 60),
            prepare_cutover_input(ArtifactDigest::from_bytes([20; 32]), 10),
        ),
        Err(MigrationError::ProductionGatesUnavailable)
    );
    assert_eq!(
        service.commit_cutover(
            command_context(0, None, 61),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: "prepared-1".to_owned(),
                observed_source_high_water: 10,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        ),
        Err(MigrationError::ProductionGatesUnavailable)
    );
    assert_eq!(
        service.begin_drain(
            command_context(0, None, 62),
            BeginDrainInput {
                plan_id: plan_id(),
                cohort: routing_unit().cohort,
            },
        ),
        Err(MigrationError::ProductionGatesUnavailable)
    );
    assert_eq!(
        service.retire_source(command_context(0, None, 63), retirement_input(),),
        Err(MigrationError::RetirementBlocked)
    );

    assert_eq!(service.load_plan(&plan_id()).unwrap(), before_plan);
    assert_eq!(service.routing_head(&routing_unit()).unwrap(), before_head);
}

#[test]
fn retirement_requires_every_exit_condition_without_mutation() {
    for missing in RetirementRequirement::ALL {
        let (service, _) = draining_service();
        let before = service.load_plan(&plan_id()).unwrap();
        let mut input = retirement_input();
        omit_retirement_requirement(&mut input.readiness, missing);

        assert_eq!(
            service.retire_source(next_context(&service), input),
            Err(MigrationError::RetirementBlocked)
        );
        assert_eq!(service.load_plan(&plan_id()).unwrap(), before);
    }
}

#[test]
fn successful_retirement_is_terminal_and_preserves_history() {
    let (service, _) = draining_service();
    let before = service.load_plan(&plan_id()).unwrap().unwrap();

    let output = service
        .retire_source(next_context(&service), retirement_input())
        .unwrap();

    assert_eq!(output.outcome.plan.phase, MigrationPhase::Retired);
    assert_eq!(output.outcome.plan.status, MigrationPlanStatus::Retired);
    let after = service.load_plan(&plan_id()).unwrap().unwrap();
    assert_eq!(
        &after.transitions[..before.transitions.len()],
        before.transitions.as_slice()
    );
    assert_eq!(after.retirement_manifests.len(), 1);
    assert_eq!(
        service.begin_drain(
            next_context(&service),
            BeginDrainInput {
                plan_id: plan_id(),
                cohort: routing_unit().cohort,
            },
        ),
        Err(MigrationError::TerminalPlanImmutable)
    );
}

#[test]
fn rollback_cycle_is_source_only_and_does_not_rewrite_parent() {
    let (service, _) = seeded_service();
    let parent_before = service.load_plan(&plan_id()).unwrap();

    let output = service
        .start_rollback_cycle(command_context(0, None, 50), rollback_input())
        .unwrap();

    assert_ne!(output.plan.plan_id, plan_id());
    assert!(matches!(
        output.snapshot.authority,
        RuntimeAuthority::Source(_)
    ));
    assert_eq!(service.load_plan(&plan_id()).unwrap(), parent_before);
}

#[test]
fn rollback_cycle_rejects_a_stale_parent_version_without_mutation() {
    let (service, _) = seeded_service();

    assert_eq!(
        service.start_rollback_cycle(command_context(1, None, 51), rollback_input()),
        Err(MigrationError::PlanVersionConflict {
            expected: 1,
            actual: 0,
        })
    );
    assert!(service.load_plan(&rollback_plan_id()).unwrap().is_none());
}

#[test]
fn emergency_revoke_restores_source_authority_and_disables_further_rollback() {
    let (service, _) = canary_active_service();
    let before_head = service.routing_head(&routing_unit()).unwrap().unwrap();
    assert_eq!(
        before_head.rollback_disposition,
        RollbackDisposition::Eligible
    );

    let output = service
        .emergency_revoke(
            emergency_revoke_context(&service),
            EmergencyRevokeInput {
                plan_id: plan_id(),
                operator_authorization: artifact("emergency-auth", 200),
                emergency_reason: "candidate-data-corruption".to_owned(),
                new_fencing_token: FencingToken::new([13; 32]).unwrap(),
            },
        )
        .unwrap();

    let snapshot = output.outcome.routing_snapshot.unwrap();
    assert!(matches!(
        snapshot.authority,
        RuntimeAuthority::Source(ref generation) if generation == &source_generation()
    ));
    assert_eq!(
        snapshot.rollback_disposition,
        RollbackDisposition::Ineligible
    );
    assert_eq!(
        snapshot.routing_generation.get(),
        before_head.routing_generation.get() + 1
    );
}

#[test]
fn emergency_revoke_is_idempotent() {
    let (service, _) = canary_active_service();
    let context = emergency_revoke_context(&service);
    let input = EmergencyRevokeInput {
        plan_id: plan_id(),
        operator_authorization: artifact("emergency-auth", 201),
        emergency_reason: "candidate-data-corruption".to_owned(),
        new_fencing_token: FencingToken::new([14; 32]).unwrap(),
    };

    let first = service
        .emergency_revoke(context.clone(), input.clone())
        .unwrap();
    let retry = service.emergency_revoke(context, input).unwrap();
    assert_eq!(
        first.outcome.routing_snapshot,
        retry.outcome.routing_snapshot
    );
}

#[test]
fn emergency_revoke_rejects_non_production_phases() {
    let (service, _) = seeded_service();

    assert_eq!(
        service.emergency_revoke(
            next_context(&service),
            EmergencyRevokeInput {
                plan_id: plan_id(),
                operator_authorization: artifact("emergency-auth", 202),
                emergency_reason: "test".to_owned(),
                new_fencing_token: FencingToken::new([15; 32]).unwrap(),
            },
        ),
        Err(MigrationError::EmergencyRevokeIneligible)
    );
}

#[test]
fn rollback_cycle_can_commit_cutover_and_restore_source_authority() {
    let (service, _) = seeded_service();
    service
        .start_rollback_cycle(command_context(0, None, 50), rollback_input())
        .unwrap();

    let rb_plan_id = rollback_plan_id();
    for target in [
        MigrationPhase::Foundation,
        MigrationPhase::ReadOnlyParity,
        MigrationPhase::SimulatedShadow,
    ] {
        service
            .record_evidence(
                rollback_next_context(&service),
                RecordEvidenceInput {
                    plan_id: rb_plan_id.clone(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        service
            .advance_phase(rollback_next_context(&service), rb_plan_id.clone(), target)
            .unwrap();
    }

    service
        .record_evidence(
            rollback_next_context(&service),
            RecordEvidenceInput {
                plan_id: rb_plan_id.clone(),
                evidence: MigrationEvidence::SimulatedShadow {
                    semantic_diff_digest: ArtifactDigest::from_bytes([14; 32]),
                    canonical_write_count: 0,
                    external_effect_count: 0,
                    client_acknowledgement_count: 0,
                },
            },
        )
        .unwrap();

    for (index, family) in GateFamily::ALL.into_iter().enumerate() {
        service
            .record_evidence(
                rollback_next_context(&service),
                RecordEvidenceInput {
                    plan_id: rb_plan_id.clone(),
                    evidence: MigrationEvidence::ProductionGate(GateEvidence {
                        gate_id: GateId::new(format!("rb-gate-{}", index + 1)).unwrap(),
                        gate_revision: 1,
                        family,
                        source_generation: candidate_generation(),
                        candidate_generation: source_generation(),
                        cohort: routing_unit().cohort,
                        contract_digest: routing_unit().contract_digest,
                        profile_digest: routing_unit().feature_profile.profile_digest,
                        config_digest: routing_unit().config_digest,
                        measured_at: Timestamp::from_unix_micros(50),
                        valid_until: Timestamp::from_unix_micros(300),
                        status: GateStatus::Passed,
                        evidence_digest: ArtifactDigest::from_bytes(
                            [u8::try_from(index + 1).unwrap(); 32],
                        ),
                    }),
                },
            )
            .unwrap();
    }

    service
        .advance_phase(
            rollback_next_context(&service),
            rb_plan_id.clone(),
            MigrationPhase::InternalCanary,
        )
        .unwrap();

    let evidence_set_digest = rollback_gate_set_digest(&service);
    let prepared = service
        .prepare_cutover(
            rollback_routing_context(&service, 2),
            PrepareCutoverInput {
                plan_id: rb_plan_id.clone(),
                intent: CutoverIntent::Rollback,
                rollout_policy: CutoverPolicy::InternalCanary(
                    CanaryPolicy::new(routing_unit().cohort, 64).unwrap(),
                ),
                manifest: artifact("rollback-manifest", 220),
                source_release: artifact("source-release", 31),
                candidate_release: artifact("candidate-release", 32),
                frozen_evidence_set: ArtifactRef::new(
                    "artifact://evidence-set",
                    evidence_set_digest,
                )
                .unwrap(),
                migration_report: MigrationReport::new(MigrationReportFields {
                    report: artifact("rb-migration-report", 221),
                    plan_id: rb_plan_id.clone(),
                    cycle_id: MigrationCycleId::new("cycle-rollback-1").unwrap(),
                    source_snapshot: artifact("rb-source-snapshot", 222),
                    source_high_water: 0,
                    source_generation: candidate_generation(),
                    candidate_generation: source_generation(),
                    counts: MigrationCounts {
                        imported: 10,
                        skipped: 0,
                        unsupported: 0,
                        rejected: 0,
                        unknown: 0,
                        lossy: 0,
                        ambiguous: 0,
                    },
                    schema: artifact("schema", 3),
                    mapping: artifact("rb-mapping", 223),
                    profile: artifact("profile", 1),
                    integrity: ArtifactValidation::Passed,
                    rebuild: ArtifactValidation::Passed,
                    disposition: ImportDisposition::Clean,
                    created_at: Timestamp::from_unix_micros(90),
                })
                .unwrap(),
                drain_report: DrainReportArtifact {
                    report: artifact("rb-drain-report", 224),
                    complete: true,
                    timed_out: false,
                    unresolved_effects: 0,
                    source_high_water: 0,
                },
                candidate_validation: CandidateValidationReport {
                    report: artifact("rb-candidate-validation", 225),
                    validation: ArtifactValidation::Passed,
                },
                rollback_policy: RollbackPolicy::BeforeCandidateWrites,
                retention_until: Timestamp::from_unix_micros(1_000),
                operator_authorization: artifact("rb-operator-authorization", 226),
            },
        )
        .unwrap();

    let committed = service
        .commit_cutover(
            rollback_routing_context(&service, 2),
            CommitCutoverInput {
                plan_id: rb_plan_id,
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 0,
                candidate_fencing_token: FencingToken::new([15; 32]).unwrap(),
            },
        )
        .unwrap();

    let snapshot = committed.outcome.routing_snapshot.unwrap();
    assert!(matches!(
        snapshot.authority,
        RuntimeAuthority::Source(ref generation) if generation == &source_generation()
    ));
    assert_eq!(
        snapshot.rollback_disposition,
        RollbackDisposition::Ineligible
    );
}

#[derive(Clone, Default)]
struct MemoryMigrationStore {
    state: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    plans: BTreeMap<String, LoadedMigrationPlan>,
    heads: BTreeMap<ArtifactDigest, RoutingSnapshot>,
    receipts: BTreeMap<
        String,
        (
            IdempotencyKey,
            MigrationCommandFingerprint,
            gocode_application::migration::ports::MigrationCommandOutcome,
        ),
    >,
}

impl MemoryMigrationStore {
    fn insert_routing_head(&self, unit: &RoutingUnit, snapshot: RoutingSnapshot) {
        self.state
            .lock()
            .unwrap()
            .heads
            .insert(unit.digest(), snapshot);
    }

    fn transition_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .plans
            .values()
            .map(|loaded| loaded.transitions.len())
            .sum()
    }

    fn evidence_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .plans
            .values()
            .map(|loaded| loaded.evidence.len())
            .sum()
    }
}

impl MigrationControlStore for MemoryMigrationStore {
    fn load_plan(
        &self,
        plan_id: &MigrationPlanId,
    ) -> Result<Option<LoadedMigrationPlan>, MigrationStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .plans
            .get(plan_id.as_str())
            .cloned())
    }

    fn load_routing_head(
        &self,
        unit: &RoutingUnit,
    ) -> Result<Option<RoutingSnapshot>, MigrationStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .heads
            .get(&unit.digest())
            .cloned())
    }

    fn lookup_receipt(
        &self,
        context: &MigrationCommandContext,
        fingerprint: &MigrationCommandFingerprint,
    ) -> Result<MigrationReceiptLookup, MigrationStoreError> {
        let state = self.state.lock().unwrap();
        let Some((stored_key, stored_fingerprint, stored_result)) =
            state.receipts.get(&context.command_id.to_string())
        else {
            return Ok(MigrationReceiptLookup::Miss);
        };
        if stored_key == &context.idempotency_key && stored_fingerprint == fingerprint {
            Ok(MigrationReceiptLookup::Duplicate {
                stored_result: Box::new(stored_result.clone()),
            })
        } else {
            Err(MigrationStoreError::IdempotencyConflict)
        }
    }

    fn commit(
        &self,
        commit: MigrationCommit,
    ) -> Result<MigrationCommitResult, MigrationStoreError> {
        let mut state = self.state.lock().unwrap();
        let command_key = commit.context().command_id.to_string();
        if let Some((stored_key, stored_fingerprint, stored_result)) =
            state.receipts.get(&command_key)
        {
            if stored_key == &commit.context().idempotency_key
                && stored_fingerprint == commit.fingerprint()
            {
                return Ok(MigrationCommitResult::Duplicate {
                    stored_result: stored_result.clone(),
                });
            }
            return Err(MigrationStoreError::IdempotencyConflict);
        }

        if let Some(existing) = state.plans.get(commit.guard_plan_id().as_str())
            && existing.plan.plan_version != commit.context().expected_plan_version
        {
            return Err(MigrationStoreError::PlanVersionConflict {
                expected: commit.context().expected_plan_version,
                actual: existing.plan.plan_version,
            });
        }

        let mutations = commit.mutations().to_vec();
        for mutation in &mutations {
            match mutation {
                MigrationMutation::InsertPlan(plan) => {
                    state.plans.insert(
                        plan.plan_id.to_string(),
                        LoadedMigrationPlan {
                            plan: plan.clone(),
                            transitions: Vec::new(),
                            evidence: Vec::new(),
                            migration_reports: Vec::new(),
                            cutover_manifests: Vec::new(),
                            rollback_manifests: Vec::new(),
                            retirement_manifests: Vec::new(),
                        },
                    );
                }
                MigrationMutation::AppendTransition(transition) => {
                    state
                        .plans
                        .get_mut(transition.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .transitions
                        .push(transition.clone());
                }
                MigrationMutation::AppendEvidence(evidence) => {
                    state
                        .plans
                        .get_mut(commit.plan().plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .evidence
                        .push(evidence.clone());
                }
                MigrationMutation::AppendMigrationReport(report) => {
                    state
                        .plans
                        .get_mut(report.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .migration_reports
                        .push(report.as_ref().clone());
                }
                MigrationMutation::AppendCutoverManifest(manifest) => {
                    state
                        .plans
                        .get_mut(manifest.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .cutover_manifests
                        .push(manifest.as_ref().clone());
                }
                MigrationMutation::AppendRollbackManifest(manifest) => {
                    state
                        .plans
                        .get_mut(manifest.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .rollback_manifests
                        .push(manifest.as_ref().clone());
                }
                MigrationMutation::AppendRetirementManifest(manifest) => {
                    state
                        .plans
                        .get_mut(manifest.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .retirement_manifests
                        .push(manifest.as_ref().clone());
                }
                MigrationMutation::AppendRoutingSnapshot(snapshot) => {
                    state
                        .heads
                        .insert(commit.plan().routing_unit.digest(), snapshot.clone());
                }
                MigrationMutation::AdvanceRoutingHead { .. }
                | MigrationMutation::InsertRuntimeBinding(_) => {}
            }
        }

        state
            .plans
            .get_mut(commit.plan().plan_id.as_str())
            .ok_or(MigrationStoreError::CorruptData)?
            .plan = commit.plan().clone();

        let outcome = commit.outcome().clone();
        let receipt = MigrationReceipt {
            command_id: commit.context().command_id,
            idempotency_key: commit.context().idempotency_key.clone(),
            fingerprint: *commit.fingerprint(),
            stored_result: outcome.clone(),
            committed_at: Timestamp::from_unix_micros(100),
        };
        state.receipts.insert(
            command_key,
            (
                commit.context().idempotency_key.clone(),
                *commit.fingerprint(),
                outcome,
            ),
        );
        Ok(MigrationCommitResult::Committed { receipt })
    }
}

#[derive(Clone, Copy)]
struct PureShadow;

impl ShadowExecutionPort for PureShadow {
    fn evaluate(
        &self,
        _input: SanitizedShadowInput,
    ) -> Result<ShadowDiffReport, ShadowExecutionError> {
        Err(ShadowExecutionError::InvalidInput)
    }
}

fn seeded_service() -> (
    MigrationService<MemoryMigrationStore, PureShadow>,
    MemoryMigrationStore,
) {
    let store = MemoryMigrationStore::default();
    let service = MigrationService::new(store.clone(), PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();
    (service, store)
}

fn shadow_ready_service() -> (
    MigrationService<MemoryMigrationStore, PureShadow>,
    MemoryMigrationStore,
) {
    let (service, store) = seeded_service();
    for target in [
        MigrationPhase::Foundation,
        MigrationPhase::ReadOnlyParity,
        MigrationPhase::SimulatedShadow,
    ] {
        service
            .record_evidence(
                next_context(&service),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        service
            .advance_phase(next_context(&service), plan_id(), target)
            .unwrap();
    }
    service
        .record_evidence(
            next_context(&service),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::SimulatedShadow {
                    semantic_diff_digest: ArtifactDigest::from_bytes([14; 32]),
                    canonical_write_count: 0,
                    external_effect_count: 0,
                    client_acknowledgement_count: 0,
                },
            },
        )
        .unwrap();
    (service, store)
}

fn canary_active_service() -> (
    MigrationService<MemoryMigrationStore, PureShadow>,
    MemoryMigrationStore,
) {
    let (service, store) = shadow_ready_service();
    record_phase4_evidence_except(&service, None);
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::InternalCanary,
        )
        .unwrap();
    let evidence_set_digest = current_gate_set_digest(&service, MigrationPhase::InternalCanary);
    let prepared = service
        .prepare_cutover(
            next_routing_generation_context(&service, 1),
            prepare_cutover_input(evidence_set_digest, 10),
        )
        .unwrap();
    service
        .commit_cutover(
            next_routing_generation_context(&service, 1),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 10,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        )
        .unwrap();
    (service, store)
}

fn draining_service() -> (
    MigrationService<MemoryMigrationStore, PureShadow>,
    MemoryMigrationStore,
) {
    let (service, store) = seeded_service();
    {
        let mut state = store.state.lock().unwrap();
        let loaded = state.plans.get_mut(plan_id().as_str()).unwrap();
        loaded.plan.phase = MigrationPhase::DrainDeprecate;
        loaded.plan.plan_version = 7;
    }
    (service, store)
}

fn record_phase4_evidence_except(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
    omitted: Option<GateFamily>,
) {
    for (index, family) in GateFamily::ALL.into_iter().enumerate() {
        if omitted == Some(family) {
            continue;
        }
        service
            .record_evidence(
                next_context(service),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: MigrationEvidence::ProductionGate(phase4_gate_evidence(
                        family,
                        GateStatus::Passed,
                        u8::try_from(index + 1).unwrap(),
                    )),
                },
            )
            .unwrap();
    }
}

fn phase4_gate_evidence(family: GateFamily, status: GateStatus, suffix: u8) -> GateEvidence {
    GateEvidence {
        gate_id: GateId::new(format!("gate-{suffix}")).unwrap(),
        gate_revision: 1,
        family,
        source_generation: source_generation(),
        candidate_generation: candidate_generation(),
        cohort: routing_unit().cohort,
        contract_digest: routing_unit().contract_digest,
        profile_digest: routing_unit().feature_profile.profile_digest,
        config_digest: routing_unit().config_digest,
        measured_at: Timestamp::from_unix_micros(50),
        valid_until: Timestamp::from_unix_micros(300),
        status,
        evidence_digest: ArtifactDigest::from_bytes([suffix; 32]),
    }
}

fn current_phase4_gate_set_digest(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> ArtifactDigest {
    current_gate_set_digest(service, MigrationPhase::InternalCanary)
}

fn current_gate_set_digest(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
    target: MigrationPhase,
) -> ArtifactDigest {
    let loaded = service.load_plan(&plan_id()).unwrap().unwrap();
    PhaseGatePolicy::for_target(target)
        .unwrap()
        .validate(
            &loaded.evidence,
            &GateContext {
                source_generation: loaded.plan.source,
                candidate_generation: loaded.plan.candidate,
                cohort: loaded.plan.routing_unit.cohort,
                contract_digest: loaded.plan.routing_unit.contract_digest,
                profile_digest: loaded.plan.routing_unit.feature_profile.profile_digest,
                config_digest: loaded.plan.routing_unit.config_digest,
                now: Timestamp::from_unix_micros(100),
            },
        )
        .unwrap()
        .digest()
}

fn next_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> MigrationCommandContext {
    let version = service
        .load_plan(&plan_id())
        .unwrap()
        .unwrap()
        .plan
        .plan_version;
    command_context(version, None, version + 2)
}

fn emergency_revoke_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> MigrationCommandContext {
    let version = service
        .load_plan(&plan_id())
        .unwrap()
        .unwrap()
        .plan
        .plan_version;
    command_context(version, None, version + 80)
}

fn rollback_next_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> MigrationCommandContext {
    let version = service
        .load_plan(&rollback_plan_id())
        .unwrap()
        .unwrap()
        .plan
        .plan_version;
    command_context_for_rb(version, 200 + version)
}

fn command_context_for_rb(
    expected_plan_version: u64,
    command_suffix: u64,
) -> MigrationCommandContext {
    MigrationCommandContext {
        command_id: format!("018f2e3a-8d5c-7b20-8d9a-{command_suffix:012x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("rb-command-{command_suffix}")).unwrap(),
        operator_id: OperatorId::new("operator-1").unwrap(),
        expected_plan_version,
        expected_routing_generation: None,
        evaluated_at: Timestamp::from_unix_micros(100),
    }
}

fn rollback_routing_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
    generation: u64,
) -> MigrationCommandContext {
    let mut context = rollback_next_context(service);
    context.expected_routing_generation = Some(RoutingGeneration::new(generation).unwrap());
    context
}

fn rollback_gate_set_digest(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> ArtifactDigest {
    let loaded = service.load_plan(&rollback_plan_id()).unwrap().unwrap();
    PhaseGatePolicy::for_target(MigrationPhase::InternalCanary)
        .unwrap()
        .validate(
            &loaded.evidence,
            &GateContext {
                source_generation: loaded.plan.source,
                candidate_generation: loaded.plan.candidate,
                cohort: loaded.plan.routing_unit.cohort,
                contract_digest: loaded.plan.routing_unit.contract_digest,
                profile_digest: loaded.plan.routing_unit.feature_profile.profile_digest,
                config_digest: loaded.plan.routing_unit.config_digest,
                now: Timestamp::from_unix_micros(100),
            },
        )
        .unwrap()
        .digest()
}

fn next_routing_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> MigrationCommandContext {
    next_routing_generation_context(service, 1)
}

fn next_routing_generation_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
    generation: u64,
) -> MigrationCommandContext {
    let mut context = next_context(service);
    context.expected_routing_generation = Some(RoutingGeneration::new(generation).unwrap());
    context
}

fn prepare_cutover_input(
    evidence_set_digest: ArtifactDigest,
    source_high_water: u64,
) -> PrepareCutoverInput {
    PrepareCutoverInput {
        plan_id: plan_id(),
        intent: CutoverIntent::InternalCanary,
        rollout_policy: CutoverPolicy::InternalCanary(
            CanaryPolicy::new(routing_unit().cohort, 64).unwrap(),
        ),
        manifest: artifact("cutover-manifest", 30),
        source_release: artifact("source-release", 31),
        candidate_release: artifact("candidate-release", 32),
        frozen_evidence_set: ArtifactRef::new("artifact://evidence-set", evidence_set_digest)
            .unwrap(),
        migration_report: MigrationReport::new(MigrationReportFields {
            report: artifact("migration-report", 33),
            plan_id: plan_id(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            source_snapshot: artifact("source-snapshot", 34),
            source_high_water,
            source_generation: source_generation(),
            candidate_generation: candidate_generation(),
            counts: MigrationCounts {
                imported: 10,
                skipped: 0,
                unsupported: 0,
                rejected: 0,
                unknown: 0,
                lossy: 0,
                ambiguous: 0,
            },
            schema: artifact("schema", 3),
            mapping: artifact("mapping", 35),
            profile: artifact("profile", 1),
            integrity: ArtifactValidation::Passed,
            rebuild: ArtifactValidation::Passed,
            disposition: ImportDisposition::Clean,
            created_at: Timestamp::from_unix_micros(90),
        })
        .unwrap(),
        drain_report: DrainReportArtifact {
            report: artifact("drain-report", 36),
            complete: true,
            timed_out: false,
            unresolved_effects: 0,
            source_high_water,
        },
        candidate_validation: CandidateValidationReport {
            report: artifact("candidate-validation", 37),
            validation: ArtifactValidation::Passed,
        },
        rollback_policy: RollbackPolicy::BeforeCandidateWrites,
        retention_until: Timestamp::from_unix_micros(1_000),
        operator_authorization: artifact("operator-authorization", 38),
    }
}

fn prepare_cohort_expansion_input(
    evidence_set_digest: ArtifactDigest,
    source_high_water: u64,
    rollout_step: RolloutStep,
    unresolved_effects: u64,
    artifact_byte: u8,
) -> PrepareCutoverInput {
    PrepareCutoverInput {
        plan_id: plan_id(),
        intent: CutoverIntent::CohortExpansion,
        rollout_policy: CutoverPolicy::CohortExpansion(rollout_step),
        manifest: artifact(&format!("cohort-manifest-{artifact_byte}"), artifact_byte),
        source_release: artifact("source-release", 31),
        candidate_release: artifact("candidate-release", 32),
        frozen_evidence_set: ArtifactRef::new("artifact://evidence-set", evidence_set_digest)
            .unwrap(),
        migration_report: MigrationReport::new(MigrationReportFields {
            report: artifact(
                &format!("cohort-migration-report-{artifact_byte}"),
                artifact_byte + 1,
            ),
            plan_id: plan_id(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            source_snapshot: artifact(
                &format!("cohort-source-snapshot-{artifact_byte}"),
                artifact_byte + 2,
            ),
            source_high_water,
            source_generation: source_generation(),
            candidate_generation: candidate_generation(),
            counts: MigrationCounts {
                imported: 10,
                skipped: 0,
                unsupported: 0,
                rejected: 0,
                unknown: 0,
                lossy: 0,
                ambiguous: 0,
            },
            schema: artifact("schema", 3),
            mapping: artifact(
                &format!("cohort-mapping-{artifact_byte}"),
                artifact_byte + 3,
            ),
            profile: artifact("profile", 1),
            integrity: ArtifactValidation::Passed,
            rebuild: ArtifactValidation::Passed,
            disposition: ImportDisposition::Clean,
            created_at: Timestamp::from_unix_micros(90),
        })
        .unwrap(),
        drain_report: DrainReportArtifact {
            report: artifact(
                &format!("cohort-drain-report-{artifact_byte}"),
                artifact_byte + 4,
            ),
            complete: true,
            timed_out: false,
            unresolved_effects,
            source_high_water,
        },
        candidate_validation: CandidateValidationReport {
            report: artifact(
                &format!("cohort-candidate-validation-{artifact_byte}"),
                artifact_byte + 5,
            ),
            validation: ArtifactValidation::Passed,
        },
        rollback_policy: RollbackPolicy::BeforeCandidateWrites,
        retention_until: Timestamp::from_unix_micros(1_000),
        operator_authorization: artifact(
            &format!("cohort-operator-authorization-{artifact_byte}"),
            artifact_byte + 6,
        ),
    }
}

fn valid_rollout_step(previous_generation: u64, admission_limit: u32) -> RolloutStep {
    RolloutStep::new(
        RoutingGeneration::new(previous_generation).unwrap(),
        routing_unit().cohort,
        admission_limit,
        Duration::from_micros(50),
        Timestamp::from_unix_micros(50),
        Timestamp::from_unix_micros(100),
        GatePolicyRef::new("policy-v1").unwrap(),
    )
    .unwrap()
}

fn artifact(name: &str, byte: u8) -> ArtifactRef {
    ArtifactRef::new(
        format!("artifact://{name}"),
        ArtifactDigest::from_bytes([byte; 32]),
    )
    .unwrap()
}

fn retirement_input() -> RetireSourceInput {
    let readiness = complete_retirement_readiness();
    RetireSourceInput {
        plan_id: plan_id(),
        manifest: RetirementManifest {
            manifest: artifact("retirement", 100),
            plan_id: plan_id(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            final_drain_report: artifact("final-drain", 101),
            reference_inventory_digest: readiness.reference_inventory.digest(),
            platform_verification_set: artifact("platform-verification", 102),
            closed_windows_evidence: artifact("closed-windows", 103),
            disabled_legacy_authority: artifact("disabled-legacy", 104),
            final_audit: artifact("final-audit", 105),
            removal_diff: artifact("removal-diff", 106),
            removal_suite: artifact("removal-suite", 107),
            retention_until: Timestamp::from_unix_micros(1_000),
            operator_authorization: artifact("retirement-authorization", 108),
            created_at: Timestamp::from_unix_micros(100),
        },
        readiness,
    }
}

fn complete_retirement_readiness() -> RetirementReadiness {
    let resolved = |byte| LegacyReferenceSet {
        blocking_count: 0,
        identity_digest: ArtifactDigest::from_bytes([byte; 32]),
        disposition: LegacyReferenceDisposition::Resolved,
    };
    RetirementReadiness {
        reference_inventory: LegacyReferenceInventory {
            active_and_in_flight: resolved(110),
            recovery_candidates: resolved(111),
            uncertain_effects: resolved(112),
            timers_processes_cleanup: resolved(113),
            replay_and_client_cursors: resolved(114),
            audit_and_retention: resolved(115),
            rollback_artifacts: resolved(116),
            credentials_packages_processes: resolved(117),
        },
        legacy_admission_closed: true,
        replacement_platforms_verified: true,
        migration_window_closed: true,
        rollback_window_closed: true,
        credentials_disabled: true,
        processes_disabled: true,
        packages_disabled: true,
        removal_suites_passed: true,
        final_audit_accepted: true,
    }
}

fn omit_retirement_requirement(
    readiness: &mut RetirementReadiness,
    requirement: RetirementRequirement,
) {
    match requirement {
        RetirementRequirement::ReferenceInventoryClear => {
            readiness
                .reference_inventory
                .active_and_in_flight
                .blocking_count = 1;
        }
        RetirementRequirement::LegacyAdmissionClosed => {
            readiness.legacy_admission_closed = false;
        }
        RetirementRequirement::ReplacementPlatformsVerified => {
            readiness.replacement_platforms_verified = false;
        }
        RetirementRequirement::MigrationWindowClosed => {
            readiness.migration_window_closed = false;
        }
        RetirementRequirement::RollbackWindowClosed => {
            readiness.rollback_window_closed = false;
        }
        RetirementRequirement::CredentialsDisabled => readiness.credentials_disabled = false,
        RetirementRequirement::ProcessesDisabled => readiness.processes_disabled = false,
        RetirementRequirement::PackagesDisabled => readiness.packages_disabled = false,
        RetirementRequirement::RemovalSuitesPassed => readiness.removal_suites_passed = false,
        RetirementRequirement::FinalAuditAccepted => readiness.final_audit_accepted = false,
    }
}

fn stage_context() -> MigrationCommandContext {
    command_context(0, None, 1)
}

fn command_context(
    expected_plan_version: u64,
    expected_routing_generation: Option<RoutingGeneration>,
    command_suffix: u64,
) -> MigrationCommandContext {
    MigrationCommandContext {
        command_id: format!("018f2e3a-8d5c-7b20-8d9a-{command_suffix:012x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("migration-command-{command_suffix}"))
            .unwrap(),
        operator_id: OperatorId::new("operator-1").unwrap(),
        expected_plan_version,
        expected_routing_generation,
        evaluated_at: Timestamp::from_unix_micros(100),
    }
}

fn stage_input() -> StagePlanInput {
    StagePlanInput {
        plan: test_plan(),
        initial_snapshot: source_snapshot(),
    }
}

fn required_evidence_for(target: MigrationPhase) -> MigrationEvidence {
    match target {
        MigrationPhase::Foundation => MigrationEvidence::Baseline {
            source_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".to_owned(),
            inventory_digest: ArtifactDigest::from_bytes([8; 32]),
            fixture_digest: ArtifactDigest::from_bytes([9; 32]),
        },
        MigrationPhase::ReadOnlyParity => MigrationEvidence::Foundation {
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            store_integrity_digest: ArtifactDigest::from_bytes([10; 32]),
            deterministic_test_digest: ArtifactDigest::from_bytes([11; 32]),
        },
        MigrationPhase::SimulatedShadow => MigrationEvidence::ReadOnlyParity {
            import_report_digest: ArtifactDigest::from_bytes([12; 32]),
            completeness_digest: ArtifactDigest::from_bytes([13; 32]),
            canonical_mutation_count: 0,
        },
        other => panic!("no source-only evidence fixture for {other:?}"),
    }
}

fn test_plan() -> MigrationPlan {
    MigrationPlan {
        plan_id: plan_id(),
        cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
        cycle_kind: MigrationCycleKind::Forward,
        source: source_generation(),
        candidate: candidate_generation(),
        phase: MigrationPhase::Baseline,
        status: MigrationPlanStatus::Active,
        routing_unit: routing_unit(),
        gate_policy: GatePolicyRef::new("policy-v1").unwrap(),
        plan_version: 0,
        created_at: Timestamp::from_unix_micros(1),
    }
}

fn source_snapshot() -> RoutingSnapshot {
    RoutingSnapshot::new(
        RoutingGeneration::new(1).unwrap(),
        source_generation(),
        candidate_generation(),
        MigrationPhase::Baseline,
        RuntimeAuthority::Source(source_generation()),
        routing_unit(),
        FencingToken::new([7; 32]).unwrap(),
        RollbackDisposition::Eligible,
        Timestamp::from_unix_micros(1),
    )
    .unwrap()
}

fn rollback_input() -> StartRollbackInput {
    StartRollbackInput {
        parent_plan_id: plan_id(),
        rollback_plan: MigrationPlan {
            plan_id: rollback_plan_id(),
            cycle_id: MigrationCycleId::new("cycle-rollback-1").unwrap(),
            cycle_kind: MigrationCycleKind::Rollback {
                parent_cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            },
            source: candidate_generation(),
            candidate: source_generation(),
            phase: MigrationPhase::Baseline,
            status: MigrationPlanStatus::Active,
            routing_unit: routing_unit(),
            gate_policy: GatePolicyRef::new("policy-v1").unwrap(),
            plan_version: 0,
            created_at: Timestamp::from_unix_micros(20),
        },
        initial_snapshot: RoutingSnapshot::new(
            RoutingGeneration::new(2).unwrap(),
            candidate_generation(),
            source_generation(),
            MigrationPhase::Baseline,
            RuntimeAuthority::Source(candidate_generation()),
            routing_unit(),
            FencingToken::new([8; 32]).unwrap(),
            RollbackDisposition::Eligible,
            Timestamp::from_unix_micros(20),
        )
        .unwrap(),
    }
}

fn plan_id() -> MigrationPlanId {
    MigrationPlanId::new("plan-1").unwrap()
}

fn rollback_plan_id() -> MigrationPlanId {
    MigrationPlanId::new("plan-rollback-1").unwrap()
}

fn source_generation() -> RuntimeGenerationRef {
    RuntimeGenerationRef::new("runtime-legacy").unwrap()
}

fn candidate_generation() -> RuntimeGenerationRef {
    RuntimeGenerationRef::new("runtime-native").unwrap()
}

fn routing_unit() -> RoutingUnit {
    RoutingUnit {
        deployment: DeploymentId::new("production").unwrap(),
        cohort: CohortSelector::new(vec![
            CohortDimension::new("client_class", "premium").unwrap(),
        ])
        .unwrap(),
        feature_profile: FeatureProfileRef::new("default", 1, ArtifactDigest::from_bytes([1; 32]))
            .unwrap(),
        contract_digest: ArtifactDigest::from_bytes([2; 32]),
        schema_digest: ArtifactDigest::from_bytes([3; 32]),
        config_digest: ArtifactDigest::from_bytes([4; 32]),
    }
}

fn unrelated_routing_unit() -> RoutingUnit {
    RoutingUnit {
        deployment: DeploymentId::new("production").unwrap(),
        cohort: CohortSelector::new(vec![
            CohortDimension::new("client_class", "standard").unwrap(),
        ])
        .unwrap(),
        feature_profile: FeatureProfileRef::new("default", 1, ArtifactDigest::from_bytes([1; 32]))
            .unwrap(),
        contract_digest: ArtifactDigest::from_bytes([2; 32]),
        schema_digest: ArtifactDigest::from_bytes([3; 32]),
        config_digest: ArtifactDigest::from_bytes([4; 32]),
    }
}

fn unrelated_source_snapshot() -> RoutingSnapshot {
    RoutingSnapshot::new(
        RoutingGeneration::new(1).unwrap(),
        source_generation(),
        candidate_generation(),
        MigrationPhase::Baseline,
        RuntimeAuthority::Source(source_generation()),
        unrelated_routing_unit(),
        FencingToken::new([6; 32]).unwrap(),
        RollbackDisposition::Eligible,
        Timestamp::from_unix_micros(1),
    )
    .unwrap()
}
