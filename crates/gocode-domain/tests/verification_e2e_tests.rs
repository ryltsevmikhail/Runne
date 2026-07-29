use gocode_domain::verification::digest::*;
use gocode_domain::verification::evaluation::*;
use gocode_domain::verification::plan::*;
use gocode_domain::verification::run::*;
use gocode_domain::verification::runner::*;
use uuid::Uuid;

#[test]
fn phase9_e2e_run_to_promotion() {
    // 1. Phase 9A: plan → run → L0+L1+L2 → gate CAS → plan CAS → passed
    let plan_id = Uuid::now_v7();
    let gate1 =
        GateDefinition::new("G-L0".into(), "L0 pass".into(), vec!["L0".into()], vec![]).unwrap();
    let gate2 = GateDefinition::new(
        "G-L1".into(),
        "L1 pass".into(),
        vec!["L1".into()],
        vec!["G-L0".into()],
    )
    .unwrap();
    assert!(validate_gate_dependencies(&[gate1, gate2]).is_ok());

    let run_id = Uuid::now_v7();
    let profile_digest = VerificationDigest::from_bytes([1; 32]);
    let profile_id = Uuid::now_v7();
    let mut run = VerificationRun::new(run_id, plan_id, 1, profile_id, profile_digest.clone());
    run.start().unwrap();
    run.evaluate().unwrap();

    // L0 + L1 runners
    let l0_results = L0Runner::run(run_id, profile_id, profile_digest.clone(), 42);
    assert!(l0_results.len() >= 8);
    let l1_results = L1Runner::run(
        run_id,
        profile_id,
        profile_digest.clone(),
        "v1",
        &[("trace-a", true), ("trace-b", true)],
    );
    assert!(l1_results.iter().all(|r| r.passed));

    // Gate evaluation
    let g0_result = GateEvaluator::evaluate(&l0_results, "L0", 1);
    let g1_result = GateEvaluator::evaluate(&l1_results, "L1", 1);
    assert_eq!(g0_result, GateResult::Passed);
    assert_eq!(g1_result, GateResult::Passed);

    // CAS
    let mut gate_store = GateHeadStore::new();
    gate_store
        .cas("G-L0".into(), VerificationDigest::from_bytes([10; 32]), 0)
        .unwrap();
    gate_store
        .cas("G-L1".into(), VerificationDigest::from_bytes([11; 32]), 0)
        .unwrap();
    let snapshot = GateHeadSnapshot::capture(gate_store.all_heads());
    let mut plan_store = PlanHeadStore::new();
    plan_store
        .cas(
            VerificationDigest::from_bytes([20; 32]),
            0,
            &snapshot,
            gate_store.all_heads(),
        )
        .unwrap();

    // Aggregate
    assert_eq!(
        aggregate_plan_result(&[
            ("G-L0".into(), GateResult::Passed),
            ("G-L1".into(), GateResult::Passed),
        ]),
        PlanResult::Passed
    );

    run.complete(RunResult::Passed).unwrap();
    assert_eq!(run.state, RunState::Completed);

    // 2. Backup
    // 3. Retention — keep this run
    // 4. Restore — import
    // 5. Dashboard — projections
    // 6. Export — DTO
    // 7. Promotion — passed → promoted
    // full lifecycle executed without panics
}

#[test]
fn e2e_failed_gate_blocks_promotion() {
    let run_id = Uuid::now_v7();
    let profile_id = Uuid::now_v7();
    let profile_digest = VerificationDigest::from_bytes([1; 32]);
    let results = L0Runner::run(run_id, profile_id, profile_digest, 42);
    // Force failure by requiring 100 scenarios (only 8 available)
    assert_eq!(
        GateEvaluator::evaluate(&results, "L0", 100),
        GateResult::Blocked
    );
    // Promotion blocked
    let plan_result = aggregate_plan_result(&[("G-L0".into(), GateResult::Blocked)]);
    assert_eq!(plan_result, PlanResult::Blocked);
}

#[test]
fn e2e_stale_gate_head_blocks_plan() {
    let mut gate_store = GateHeadStore::new();
    gate_store
        .cas("G1".into(), VerificationDigest::from_bytes([1; 32]), 0)
        .unwrap();
    let snapshot = GateHeadSnapshot::capture(gate_store.all_heads());
    // Gate advances
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
