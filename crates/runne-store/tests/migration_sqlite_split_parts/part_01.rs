use std::{
    path::Path,
    sync::{Arc, Barrier},
    thread,
};

use runne_application::migration::{
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
    rollout::{CanaryPolicy, CutoverPolicy},
    service::{
        CommitCutoverInput, CutoverIntent, MigrationService, PrepareCutoverInput,
        RecordEvidenceInput, StagePlanInput, StartRollbackInput,
    },
    state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
    types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        FencingToken, GateFamily, GateId, GatePolicyRef, MigrationCycleId, MigrationPlanId,
        OperatorId, RollbackDisposition, RoutingGeneration, RoutingSnapshot, RoutingUnit,
        RuntimeAuthority, RuntimeGenerationRef,
    },
};
use runne_domain::{
    id::{CommandId, IdempotencyKey},
    timestamp::Timestamp,
};
use runne_store::migration_store::SqliteMigrationControlStore;
use rusqlite::Connection;

#[test]
fn two_writers_racing_same_routing_generation_have_one_winner() {
    let db = TempDb::new("routing-cas");
    let left = SqliteMigrationControlStore::open(db.path()).unwrap();
    assert!(SqliteMigrationControlStore::open(db.path()).is_err());
    let right = db.adopt();
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

    let connection = db.reader();
    let snapshot_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM routing_snapshots", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(snapshot_count, 2);
}

#[test]
fn direct_stage_seven_commit_is_rejected_without_durable_effects() {
    let db = TempDb::new("stage-seven-direct-commit");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    store.commit(stage_commit()).unwrap();
    let before = durable_counts(&db.reader());

    let loaded = store.load_plan(&plan_id()).unwrap().unwrap();
    let mut plan = loaded.plan;
    plan.phase = MigrationPhase::DrainDeprecate;
    plan.plan_version += 1;
    let context = command_context(9, 0, None);
    let transition = MigrationTransition {
        transition_id: "direct-stage-seven".into(),
        plan_id: plan.plan_id.clone(),
        cycle_id: plan.cycle_id.clone(),
        from: MigrationPhase::DefaultNative,
        to: MigrationPhase::DrainDeprecate,
        plan_version: plan.plan_version,
        occurred_at: context.evaluated_at,
    };
    let outcome = MigrationCommandOutcome {
        plan: plan.clone(),
        routing_snapshot: None,
        transition_id: transition.transition_id.clone(),
    };
    let commit = MigrationCommit::new(
        context.clone(),
        fingerprint(9),
        plan.clone(),
        vec![MigrationMutation::AppendTransition(transition)],
        outcome,
        Some(audit(
            &context,
            &plan,
            MigrationAuditAction::AdvancePhase,
            9,
        )),
    )
    .unwrap();

    let result = store.commit(commit);

    assert_eq!(
        result,
        Err(MigrationStoreError::LifecycleAuthorityRequired {
            target: MigrationPhase::DrainDeprecate,
        })
    );
    assert_eq!(
        durable_counts(&db.reader()),
        before
    );
}

#[test]
fn audit_failure_rolls_back_plan_snapshot_head_and_receipt() {
    let db = TempDb::new("audit-rollback");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let connection = db.writer();
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
    let connection = db.writer();
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
        runne_store::migration_codec::encode_migration_evidence(&MigrationEvidence::Baseline {
            source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            inventory_digest: ArtifactDigest::from_bytes([8; 32]),
            fixture_digest: ArtifactDigest::from_bytes([9; 32]),
        })
        .unwrap();
    let connection = db.writer();
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
    let connection = db.reader();
    assert_eq!(row_count(&connection, "migration_plans"), 1);
    assert_eq!(row_count(&connection, "routing_snapshots"), 1);
    assert_eq!(row_count(&connection, "routing_head"), 1);
}
