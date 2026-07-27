use std::{
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use gocode_application::migration::{
    gates::{GateContext, GateEvidence, GateStatus, MigrationEvidence, PhaseGatePolicy},
    manifests::{
        ArtifactRef, ArtifactValidation, CandidateValidationReport, DrainReportArtifact,
        ImportDisposition, MigrationCounts, MigrationReport, MigrationReportFields, RollbackPolicy,
    },
    ports::{
        MigrationAuditAction, MigrationAuditRecord, MigrationCommandContext,
        MigrationCommandFingerprint, MigrationCommandOutcome, MigrationCommit,
        MigrationControlStore, MigrationMutation, MigrationReceiptLookup, MigrationStoreError,
        MigrationTransition, SanitizedShadowInput, ShadowDiffReport, ShadowExecutionError,
        ShadowExecutionPort,
    },
    service::{
        CutoverIntent, MigrationService, PrepareCutoverInput, RecordEvidenceInput, StagePlanInput,
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
use gocode_store::{migration_store::SqliteMigrationControlStore, schema::open_with_pragmas};
use rusqlite::Connection;

#[test]
fn two_writers_racing_same_routing_generation_have_one_winner() {
    let db = TempDb::new("routing-cas");
    let left = SqliteMigrationControlStore::open(db.path()).unwrap();
    let right = SqliteMigrationControlStore::open(db.path()).unwrap();
    left.commit(stage_commit()).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let left_barrier = Arc::clone(&barrier);
    let left_thread = thread::spawn(move || {
        left_barrier.wait();
        left.commit(routing_commit(2))
    });
    let right_barrier = Arc::clone(&barrier);
    let right_thread = thread::spawn(move || {
        right_barrier.wait();
        right.commit(routing_commit(3))
    });

    let results = [left_thread.join().unwrap(), right_thread.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(MigrationStoreError::RoutingGenerationConflict {
                        expected,
                        actual,
                    }) if expected.get() == 1 && actual.get() == 2
                )
            })
            .count(),
        1
    );

    let connection = Connection::open(db.path()).unwrap();
    let snapshot_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM routing_snapshots", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(snapshot_count, 2);
}

#[test]
fn audit_failure_rolls_back_plan_snapshot_head_and_receipt() {
    let db = TempDb::new("audit-rollback");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let connection = open_with_pragmas(db.path().to_str().unwrap()).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_migration_audit
             BEFORE INSERT ON migration_audit
             BEGIN
                 SELECT RAISE(ABORT, 'audit failure');
             END;",
        )
        .unwrap();
    let before = durable_counts(&connection);

    assert_eq!(
        store.commit(stage_commit()),
        Err(MigrationStoreError::IntegrityViolation)
    );
    assert_eq!(durable_counts(&connection), before);
}

#[test]
fn reopen_restores_exact_plan_head_and_receipt() {
    let db = TempDb::new("migration-reopen");
    let original = SqliteMigrationControlStore::open(db.path()).unwrap();
    let context = stage_context();
    let fingerprint = fingerprint(1);
    let result = original.commit(stage_commit()).unwrap();
    drop(original);

    let reopened = SqliteMigrationControlStore::open(db.path()).unwrap();
    assert_eq!(
        reopened.load_plan(&plan_id()).unwrap().unwrap().plan,
        result.plan().clone()
    );
    assert_eq!(
        reopened.load_routing_head(&routing_unit()).unwrap(),
        result.outcome().routing_snapshot
    );
    assert_eq!(
        reopened.lookup_receipt(&context, &fingerprint).unwrap(),
        MigrationReceiptLookup::Duplicate {
            stored_result: Box::new(result.outcome().clone()),
        }
    );
}

#[test]
fn load_plan_rejects_normalized_candidate_mismatch() {
    let db = TempDb::new("normalized-plan-corruption");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    store.commit(stage_commit()).unwrap();
    let connection = open_with_pragmas(db.path().to_str().unwrap()).unwrap();
    connection
        .execute(
            "UPDATE migration_plans
             SET candidate_generation = 'runtime-corrupted'
             WHERE plan_id = ?1",
            [plan_id().as_str()],
        )
        .unwrap();

    assert_eq!(
        store.load_plan(&plan_id()),
        Err(MigrationStoreError::CorruptData)
    );
}

#[test]
fn load_plan_rejects_evidence_blob_that_does_not_match_its_digest() {
    let db = TempDb::new("evidence-corruption");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    store.commit(stage_commit()).unwrap();
    store.commit(evidence_commit()).unwrap();
    let replacement =
        gocode_store::migration_codec::encode_migration_evidence(&MigrationEvidence::Baseline {
            source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            inventory_digest: ArtifactDigest::from_bytes([8; 32]),
            fixture_digest: ArtifactDigest::from_bytes([9; 32]),
        })
        .unwrap();
    let connection = open_with_pragmas(db.path().to_str().unwrap()).unwrap();
    connection
        .execute(
            "UPDATE migration_evidence SET evidence_blob = ?1",
            [replacement],
        )
        .unwrap();

    assert_eq!(
        store.load_plan(&plan_id()),
        Err(MigrationStoreError::CorruptData)
    );
}

#[test]
fn second_forward_plan_cannot_silently_reuse_an_existing_routing_head() {
    let db = TempDb::new("routing-head-reuse");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    store.commit(stage_commit()).unwrap();
    let mut second_plan = test_plan();
    second_plan.plan_id = MigrationPlanId::new("plan-2").unwrap();
    second_plan.cycle_id = MigrationCycleId::new("cycle-2").unwrap();

    assert_eq!(
        store.commit(stage_commit_for(
            second_plan,
            source_snapshot(RoutingGeneration::new(2).unwrap()),
            5,
        )),
        Err(MigrationStoreError::IntegrityViolation)
    );
    let connection = Connection::open(db.path()).unwrap();
    assert_eq!(row_count(&connection, "migration_plans"), 1);
    assert_eq!(row_count(&connection, "routing_snapshots"), 1);
    assert_eq!(row_count(&connection, "routing_head"), 1);
}

#[test]
fn full_baseline_to_shadow_lifecycle_remains_source_only_in_sqlite() {
    let db = TempDb::new("baseline-to-shadow");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(store, PureShadow);
    let staged = service.stage_plan(stage_context(), stage_input()).unwrap();
    let mut expected_version = staged.plan.plan_version;
    let phases = [
        (MigrationPhase::Foundation, 2_u8, 3_u8),
        (MigrationPhase::ReadOnlyParity, 4, 5),
        (MigrationPhase::SimulatedShadow, 6, 7),
    ];

    for (target, evidence_suffix, advance_suffix) in phases {
        service
            .record_evidence(
                command_context(evidence_suffix, expected_version, None),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        expected_version += 1;
        let advanced = service
            .advance_phase(
                command_context(advance_suffix, expected_version, None),
                plan_id(),
                target,
            )
            .unwrap();
        expected_version = advanced.plan.plan_version;
        assert!(matches!(
            service
                .routing_head(&routing_unit())
                .unwrap()
                .unwrap()
                .authority,
            RuntimeAuthority::Source(_)
        ));
    }

    let loaded = service.load_plan(&plan_id()).unwrap().unwrap();
    assert_eq!(loaded.plan.phase, MigrationPhase::SimulatedShadow);
    assert_eq!(loaded.plan.plan_version, 6);
    assert_eq!(loaded.transitions.len(), 4);
    assert_eq!(loaded.evidence.len(), 3);
}

#[test]
fn duplicate_stage_and_evidence_commands_replay_original_outcomes() {
    let db = TempDb::new("duplicate-control");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(store, PureShadow);

    let staged = service.stage_plan(stage_context(), stage_input()).unwrap();
    let stage_retry = service.stage_plan(stage_context(), stage_input()).unwrap();
    assert_eq!(staged, stage_retry);
    let evidence_context = command_context(2, 0, None);
    let evidence_input = RecordEvidenceInput {
        plan_id: plan_id(),
        evidence: required_evidence_for(MigrationPhase::Foundation),
    };
    let evidence = service
        .record_evidence(evidence_context.clone(), evidence_input.clone())
        .unwrap();
    let evidence_retry = service
        .record_evidence(evidence_context, evidence_input)
        .unwrap();
    assert_eq!(evidence, evidence_retry);

    let connection = Connection::open(db.path()).unwrap();
    assert_eq!(row_count(&connection, "migration_transitions"), 1);
    assert_eq!(row_count(&connection, "migration_evidence"), 1);
    assert_eq!(row_count(&connection, "migration_receipts"), 2);
    assert_eq!(row_count(&connection, "migration_audit"), 2);
}

#[test]
fn crash_reopen_preserves_phase_evidence_and_source_head() {
    let db = TempDb::new("control-reopen");
    let original_store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(original_store, PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();
    service
        .record_evidence(
            command_context(2, 0, None),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: required_evidence_for(MigrationPhase::Foundation),
            },
        )
        .unwrap();
    service
        .advance_phase(
            command_context(3, 1, None),
            plan_id(),
            MigrationPhase::Foundation,
        )
        .unwrap();
    let before_plan = service.load_plan(&plan_id()).unwrap().unwrap();
    let before_head = service.routing_head(&routing_unit()).unwrap();
    drop(service);

    let reopened_store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let reopened = MigrationService::new(reopened_store, PureShadow);
    assert_eq!(
        reopened.load_plan(&plan_id()).unwrap().unwrap(),
        before_plan
    );
    assert_eq!(reopened.routing_head(&routing_unit()).unwrap(), before_head);
    assert!(matches!(
        before_head.unwrap().authority,
        RuntimeAuthority::Source(_)
    ));
}

#[test]
fn stale_plan_version_changes_no_durable_rows() {
    let db = TempDb::new("stale-plan");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(store, PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();
    let connection = Connection::open(db.path()).unwrap();
    let before = migration_durable_counts(&connection);

    assert!(
        service
            .advance_phase(
                command_context(2, 99, None),
                plan_id(),
                MigrationPhase::Foundation,
            )
            .is_err()
    );
    assert_eq!(migration_durable_counts(&connection), before);
}

#[test]
fn rollback_cycle_starts_at_baseline_without_mutating_parent() {
    let db = TempDb::new("rollback-cycle");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(store, PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();
    let parent = service.load_plan(&plan_id()).unwrap().unwrap();

    let rollback = service
        .start_rollback_cycle(command_context(8, 0, None), rollback_input())
        .unwrap();

    assert_eq!(rollback.plan.phase, MigrationPhase::Baseline);
    assert_ne!(rollback.plan.cycle_id, parent.plan.cycle_id);
    assert_eq!(service.load_plan(&plan_id()).unwrap().unwrap(), parent);
    assert!(matches!(
        rollback.snapshot.authority,
        RuntimeAuthority::Source(_)
    ));
    assert_eq!(
        service
            .routing_head(&routing_unit())
            .unwrap()
            .unwrap()
            .routing_generation,
        RoutingGeneration::new(1).unwrap()
    );
}

#[test]
fn prepared_gate_set_and_source_high_water_survive_reopen() {
    let db = TempDb::new("prepared-cutover-reopen");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(store, PureShadow);
    let mut version = service
        .stage_plan(stage_context(), stage_input())
        .unwrap()
        .plan
        .plan_version;
    for (target, evidence_suffix, advance_suffix) in [
        (MigrationPhase::Foundation, 2_u8, 3_u8),
        (MigrationPhase::ReadOnlyParity, 4, 5),
        (MigrationPhase::SimulatedShadow, 6, 7),
    ] {
        service
            .record_evidence(
                command_context(evidence_suffix, version, None),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        version += 1;
        version = service
            .advance_phase(
                command_context(advance_suffix, version, None),
                plan_id(),
                target,
            )
            .unwrap()
            .plan
            .plan_version;
    }
    service
        .record_evidence(
            command_context(8, version, None),
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
    version += 1;
    for (index, family) in GateFamily::ALL.into_iter().enumerate() {
        let suffix = u8::try_from(index + 20).unwrap();
        service
            .record_evidence(
                command_context(suffix, version, None),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: MigrationEvidence::ProductionGate(gate_evidence(family, suffix)),
                },
            )
            .unwrap();
        version += 1;
    }
    let loaded = service.load_plan(&plan_id()).unwrap().unwrap();
    let evidence_set_digest = PhaseGatePolicy::for_target(MigrationPhase::InternalCanary)
        .unwrap()
        .validate(
            &loaded.evidence,
            &GateContext {
                source_generation: loaded.plan.source.clone(),
                candidate_generation: loaded.plan.candidate.clone(),
                cohort: loaded.plan.routing_unit.cohort.clone(),
                contract_digest: loaded.plan.routing_unit.contract_digest,
                profile_digest: loaded.plan.routing_unit.feature_profile.profile_digest,
                config_digest: loaded.plan.routing_unit.config_digest,
                now: Timestamp::from_unix_micros(100),
            },
        )
        .unwrap()
        .digest();
    let prepared = service
        .prepare_cutover(
            command_context(40, version, Some(RoutingGeneration::new(1).unwrap())),
            prepare_cutover_input(evidence_set_digest, 4242),
        )
        .unwrap();
    let before = service.load_plan(&plan_id()).unwrap().unwrap();
    assert_eq!(before.cutover_manifests.len(), 1);
    assert_eq!(before.migration_reports.len(), 1);
    assert_eq!(before.cutover_manifests[0].source_high_water, 4242);
    assert_eq!(
        before.cutover_manifests[0].prepared_transition_id,
        prepared.outcome.transition_id
    );
    drop(service);

    let reopened = SqliteMigrationControlStore::open(db.path()).unwrap();
    assert_eq!(reopened.load_plan(&plan_id()).unwrap().unwrap(), before);
    drop(reopened);

    let connection = open_with_pragmas(db.path().to_str().unwrap()).unwrap();
    connection
        .execute("DELETE FROM migration_reports", [])
        .unwrap();
    drop(connection);
    let corrupted = SqliteMigrationControlStore::open(db.path()).unwrap();
    assert_eq!(
        corrupted.load_plan(&plan_id()),
        Err(MigrationStoreError::CorruptData)
    );
}

fn stage_commit() -> MigrationCommit {
    stage_commit_for(
        test_plan(),
        source_snapshot(RoutingGeneration::new(1).unwrap()),
        1,
    )
}

fn stage_input() -> StagePlanInput {
    StagePlanInput {
        plan: test_plan(),
        initial_snapshot: source_snapshot(RoutingGeneration::new(1).unwrap()),
    }
}

fn stage_commit_for(plan: MigrationPlan, snapshot: RoutingSnapshot, suffix: u8) -> MigrationCommit {
    let context = command_context(suffix, 0, None);
    let fingerprint = fingerprint(suffix);
    let transition = transition(&format!("transition-stage-{suffix}"), &plan);
    let outcome = MigrationCommandOutcome {
        plan: plan.clone(),
        routing_snapshot: Some(snapshot.clone()),
        transition_id: transition.transition_id.clone(),
    };
    let audit = audit(&context, &plan, MigrationAuditAction::StagePlan, suffix);

    MigrationCommit::new(
        context,
        fingerprint,
        plan.clone(),
        vec![
            MigrationMutation::InsertPlan(plan),
            MigrationMutation::AppendTransition(transition),
            MigrationMutation::AppendRoutingSnapshot(snapshot),
        ],
        outcome,
        Some(audit),
    )
    .unwrap()
}

fn routing_commit(suffix: u8) -> MigrationCommit {
    let plan = test_plan();
    let snapshot = source_snapshot(RoutingGeneration::new(2).unwrap());
    let context = command_context(suffix, 0, Some(RoutingGeneration::new(1).unwrap()));
    let fingerprint = fingerprint(suffix);
    let outcome = MigrationCommandOutcome {
        plan: plan.clone(),
        routing_snapshot: Some(snapshot.clone()),
        transition_id: format!("routing-{suffix}"),
    };
    let audit = audit(
        &context,
        &plan,
        MigrationAuditAction::PrepareCutover,
        suffix,
    );

    MigrationCommit::new(
        context,
        fingerprint,
        plan,
        vec![
            MigrationMutation::AppendRoutingSnapshot(snapshot),
            MigrationMutation::AdvanceRoutingHead {
                unit_digest: routing_unit().digest(),
                expected: RoutingGeneration::new(1).unwrap(),
                next: RoutingGeneration::new(2).unwrap(),
            },
        ],
        outcome,
        Some(audit),
    )
    .unwrap()
}

fn evidence_commit() -> MigrationCommit {
    let mut plan = test_plan();
    plan.record_mutation(0).unwrap();
    let context = command_context(4, 0, None);
    let fingerprint = fingerprint(4);
    let evidence = MigrationEvidence::Baseline {
        source_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".to_owned(),
        inventory_digest: ArtifactDigest::from_bytes([8; 32]),
        fixture_digest: ArtifactDigest::from_bytes([9; 32]),
    };
    let outcome = MigrationCommandOutcome {
        plan: plan.clone(),
        routing_snapshot: None,
        transition_id: "evidence-4".to_owned(),
    };
    let audit = audit(&context, &plan, MigrationAuditAction::RecordEvidence, 4);
    MigrationCommit::new(
        context,
        fingerprint,
        plan,
        vec![MigrationMutation::AppendEvidence(evidence)],
        outcome,
        Some(audit),
    )
    .unwrap()
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

fn gate_evidence(family: GateFamily, suffix: u8) -> GateEvidence {
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
        status: GateStatus::Passed,
        evidence_digest: ArtifactDigest::from_bytes([suffix; 32]),
    }
}

fn rollback_input() -> StartRollbackInput {
    let rollback_plan = MigrationPlan {
        plan_id: MigrationPlanId::new("plan-rollback-1").unwrap(),
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
    };
    StartRollbackInput {
        parent_plan_id: plan_id(),
        rollback_plan,
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

fn stage_context() -> MigrationCommandContext {
    command_context(1, 0, None)
}

fn command_context(
    command_suffix: u8,
    expected_plan_version: u64,
    expected_routing_generation: Option<RoutingGeneration>,
) -> MigrationCommandContext {
    MigrationCommandContext {
        command_id: format!("018f2e3a-8d5c-7b20-8d9a-{command_suffix:012x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("migration-{command_suffix}")).unwrap(),
        operator_id: OperatorId::new("operator-1").unwrap(),
        expected_plan_version,
        expected_routing_generation,
        evaluated_at: Timestamp::from_unix_micros(100),
    }
}

fn prepare_cutover_input(
    evidence_set_digest: ArtifactDigest,
    source_high_water: u64,
) -> PrepareCutoverInput {
    PrepareCutoverInput {
        plan_id: plan_id(),
        intent: CutoverIntent::InternalCanary,
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

fn artifact(name: &str, byte: u8) -> ArtifactRef {
    ArtifactRef::new(
        format!("artifact://{name}"),
        ArtifactDigest::from_bytes([byte; 32]),
    )
    .unwrap()
}

fn fingerprint(suffix: u8) -> MigrationCommandFingerprint {
    MigrationCommandFingerprint::from_bytes([suffix; 32])
}

fn audit(
    context: &MigrationCommandContext,
    plan: &MigrationPlan,
    action: MigrationAuditAction,
    suffix: u8,
) -> MigrationAuditRecord {
    MigrationAuditRecord {
        record_id: ArtifactDigest::from_bytes([suffix; 32]),
        plan_id: plan.plan_id.clone(),
        command_id: context.command_id,
        operator_id: context.operator_id.clone(),
        action,
        recorded_at: Timestamp::from_unix_micros(i64::from(suffix)),
    }
}

fn transition(identity: &str, plan: &MigrationPlan) -> MigrationTransition {
    MigrationTransition {
        transition_id: identity.to_owned(),
        plan_id: plan.plan_id.clone(),
        cycle_id: plan.cycle_id.clone(),
        from: MigrationPhase::Baseline,
        to: MigrationPhase::Baseline,
        plan_version: plan.plan_version,
        occurred_at: Timestamp::from_unix_micros(1),
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

fn source_snapshot(routing_generation: RoutingGeneration) -> RoutingSnapshot {
    RoutingSnapshot::new(
        routing_generation,
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

fn plan_id() -> MigrationPlanId {
    MigrationPlanId::new("plan-1").unwrap()
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

fn durable_counts(connection: &Connection) -> [i64; 5] {
    [
        row_count(connection, "migration_plans"),
        row_count(connection, "routing_snapshots"),
        row_count(connection, "routing_head"),
        row_count(connection, "migration_receipts"),
        row_count(connection, "migration_audit"),
    ]
}

fn migration_durable_counts(connection: &Connection) -> [i64; 7] {
    [
        row_count(connection, "migration_plans"),
        row_count(connection, "migration_transitions"),
        row_count(connection, "migration_evidence"),
        row_count(connection, "routing_snapshots"),
        row_count(connection, "routing_head"),
        row_count(connection, "migration_receipts"),
        row_count(connection, "migration_audit"),
    ]
}

fn row_count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self {
            path: std::env::temp_dir().join(format!(
                "gocode-migration-{name}-{}-{nonce}.sqlite",
                std::process::id()
            )),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
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
