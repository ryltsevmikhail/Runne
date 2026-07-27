use gocode_domain::verification::digest::*;
use gocode_domain::verification::evaluation::*;
use gocode_domain::verification::evidence::*;
use gocode_domain::verification::plan::*;
use gocode_domain::verification::run::*;
use gocode_domain::verification::runner::*;
use uuid::Uuid;

#[test]
fn full_verification_lifecycle_passes() {
    // 1. Create plan with gates
    let gate1 =
        GateDefinition::new("G1".into(), "pass L0".into(), vec!["L0".into()], vec![]).unwrap();
    let gate2 = GateDefinition::new(
        "G2".into(),
        "pass L1".into(),
        vec!["L1".into()],
        vec!["G1".into()],
    )
    .unwrap();
    assert!(validate_gate_dependencies(&[gate1.clone(), gate2.clone()]).is_ok());
    let plan = VerificationPlan::new(
        Uuid::now_v7(),
        "test".into(),
        "all pass".into(),
        vec![gate1, gate2],
        "v1".into(),
    );

    // 2. Create run
    let run_id = Uuid::now_v7();
    let profile_digest = VerificationDigest::from_bytes([1; 32]);
    let profile_id = Uuid::now_v7();
    let mut run = VerificationRun::new(
        run_id,
        plan.plan_id,
        plan.revision,
        Uuid::now_v7(),
        profile_digest.clone(),
    );
    run.start().unwrap();
    run.evaluate().unwrap();

    // 3. L0 runner produces evidence
    let l0_output = L0Runner::run(run_id, profile_id, profile_digest.clone(), 42);
    assert!(l0_output[0].passed);

    // 4. L1 runner
    let l1_output = L1Runner::run(
        run_id,
        profile_id,
        profile_digest.clone(),
        "v1",
        &[("l1/test", true)],
    );
    assert!(l1_output[0].passed);

    // 5. Gate evaluations via CAS
    let mut gate_store = GateHeadStore::new();
    let g1_ref = gate_store
        .cas(
            "G1".into(),
            l0_output[0].evidence.evidence_digest.clone(),
            0,
        )
        .unwrap();
    assert_eq!(g1_ref.generation, 1);
    let g2_ref = gate_store
        .cas(
            "G2".into(),
            l1_output[0].evidence.evidence_digest.clone(),
            0,
        )
        .unwrap();
    assert_eq!(g2_ref.generation, 1);

    // 6. GateHeadSnapshot
    let snapshot = GateHeadSnapshot::capture(gate_store.all_heads());
    assert!(
        snapshot
            .verify_against_current(gate_store.all_heads())
            .is_ok()
    );

    // 7. Plan evaluation via CAS
    let mut plan_store = PlanHeadStore::new();
    let plan_ref = plan_store
        .cas(
            VerificationDigest::from_bytes([10; 32]),
            0,
            &snapshot,
            gate_store.all_heads(),
        )
        .unwrap();
    assert_eq!(plan_ref.generation, 1);

    // 8. Aggregate result
    let results = vec![
        ("G1".to_string(), GateResult::Passed),
        ("G2".to_string(), GateResult::Passed),
    ];
    assert_eq!(aggregate_plan_result(&results), PlanResult::Passed);

    // 9. Run completes
    run.complete(RunResult::Passed).unwrap();
    assert_eq!(run.state, RunState::Completed);
}

#[test]
fn stale_gate_head_blocks_plan_cas() {
    let mut gate_store = GateHeadStore::new();
    gate_store
        .cas("G1".into(), VerificationDigest::from_bytes([1; 32]), 0)
        .unwrap();
    let snapshot = GateHeadSnapshot::capture(gate_store.all_heads());

    // Gate advances after snapshot
    gate_store
        .cas("G1".into(), VerificationDigest::from_bytes([2; 32]), 1)
        .unwrap();

    let mut plan_store = PlanHeadStore::new();
    assert!(
        plan_store
            .cas(
                VerificationDigest::from_bytes([10; 32]),
                0,
                &snapshot,
                gate_store.all_heads()
            )
            .is_err()
    );
}

#[test]
fn consumption_intent_reserve_claim_settle() {
    let mut store = IntentStore::new();
    let id = Uuid::now_v7();
    let sd = VerificationDigest::from_bytes([1; 32]);
    let td = VerificationDigest::from_bytes([2; 32]);

    store.reserve(id, "key1", sd, td).unwrap();
    store
        .claim_dispatching(&id, &VerificationDigest::from_bytes([0; 32]))
        .unwrap();
    store.settle(&id, true).unwrap();
}

#[test]
fn consumption_intent_invalidated_by_gate_cas() {
    let mut store = IntentStore::new();
    let id = Uuid::now_v7();
    store
        .reserve(
            id,
            "key1",
            VerificationDigest::from_bytes([1; 32]),
            VerificationDigest::from_bytes([2; 32]),
        )
        .unwrap();
    store.invalidate(&id).unwrap();
    assert!(
        store
            .claim_dispatching(&id, &VerificationDigest::from_bytes([0; 32]))
            .is_err()
    );
}

#[test]
fn consumption_intent_not_invalidated_after_dispatching() {
    let mut store = IntentStore::new();
    let id = Uuid::now_v7();
    store
        .reserve(
            id,
            "key1",
            VerificationDigest::from_bytes([1; 32]),
            VerificationDigest::from_bytes([2; 32]),
        )
        .unwrap();
    store
        .claim_dispatching(&id, &VerificationDigest::from_bytes([0; 32]))
        .unwrap();
    // Invalidate is no-op when already dispatching
    store.invalidate(&id).unwrap();
    // Can still settle
    store.settle(&id, true).unwrap();
}

#[test]
fn l4_budget_atomic_reserve() {
    let mut auth = L4Authorization::new(10, 100, 0, 0, 0);
    assert!(auth.reserve(5, 50, 0, 0, 0).is_ok());
    assert_eq!(auth.used_requests, 5);
    assert_eq!(auth.used_tokens, 50);
}

#[test]
fn duplicate_evidence_ref_rejected() {
    let run_id = Uuid::now_v7();
    let d = VerificationDigest::from_bytes([1; 32]);
    let i1 = EvidenceItem {
        evidence_ref_id: Uuid::now_v7(),
        run_id,
        profile_id: Uuid::now_v7(),
        profile_digest: d.clone(),
        layer: EvidenceLayer::L0,
        evidence_type: EvidenceType::TestResult,
        evidence_digest: d.clone(),
        content_ref: "blob:1".into(),
        source: "test".into(),
        producer_identity: "test".into(),
        sensitivity: SensitivityLabel::Public,
        verified_by: "test".into(),
    };
    let i2 = i1.clone();
    assert!(EvidenceSet::new(vec![i1, i2]).is_err());
}
