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
