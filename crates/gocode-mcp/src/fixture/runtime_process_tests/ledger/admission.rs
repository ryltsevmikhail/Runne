use std::panic::{AssertUnwindSafe, catch_unwind};

use super::super::super::FixtureMcpFailure;
use super::super::super::runtime::process_ledger::{ProcessPhaseOutcome, ProcessRefundReason};
use super::super::routing::support::{Probe, process_phases, ready};
use super::support::*;

#[test]
fn validation_success_records_witness_before_commit() {
    let runtime = runtime(1);
    let (_, receipt, mut pending, validated) = reserved_pending(&runtime);
    let identity = receipt.identity();
    let port = runtime.process_ledger_port();
    let guard = port
        .begin_admission(identity.clone(), pending.admission_evidence())
        .unwrap();
    let mut events = vec!["validate success"];
    let token = pending.store_validated(validated, &identity);
    events.push("store_validated/token");
    guard.commit(token);
    events.push("guard.commit");
    events.push("Winner");
    assert_eq!(
        events,
        [
            "validate success",
            "store_validated/token",
            "guard.commit",
            "Winner"
        ]
    );
    assert!(matches!(
        runtime
            .process_ledger_port()
            .settle_completed(receipt, pending),
        ProcessPhaseOutcome::EffectCompleted { .. }
    ));
}

#[test]
fn validation_error_leaves_reserved_without_replay_then_valid_succeeds() {
    let fixture = ready(
        Probe::AdvanceAuthorization,
        1,
        super::super::super::FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let (key, payload) = super::super::routing::support::key_payload(&fixture, "final-validation");
    let receipt = match fixture.runtime.reserve_process(key) {
        Ok(super::super::super::runtime::process_ledger::ProcessReserveOutcome::Owner(receipt)) => {
            receipt
        }
        _ => panic!("expected reserved owner"),
    };
    let expected_identity = receipt.identity();
    let (receipt, payload) = match fixture
        .runtime
        .dispatch_reserved_process_gateway_for_test(receipt, payload)
        .unwrap()
    {
        ProcessPhaseOutcome::PreEffectDenied {
            failure:
                super::super::super::runtime::process_ledger::ProcessPreEffectFailure::Authorization,
            receipt: returned,
            payload,
        } => {
            assert_eq!(returned.identity(), expected_identity);
            (returned, *payload)
        }
        _ => panic!("expected final authorization denial"),
    };
    assert_eq!(
        process_phases(&fixture.runtime),
        [super::super::super::FixtureAuditProcessPhase::Reserved]
    );
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        Some(0)
    );

    assert!(
        payload
            .mcp()
            .verify_c2b(payload.material().intent())
            .is_ok()
    );
    let (_, current) = super::super::routing::support::key_payload(&fixture, "final-validation");
    assert!(matches!(
        fixture
            .runtime
            .dispatch_reserved_process_gateway_for_test(receipt, current),
        Ok(ProcessPhaseOutcome::EffectUncertain { .. })
    ));
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        Some(1)
    );
    assert_eq!(
        process_phases(&fixture.runtime),
        [
            super::super::super::FixtureAuditProcessPhase::Reserved,
            super::super::super::FixtureAuditProcessPhase::Admitted,
            super::super::super::FixtureAuditProcessPhase::Uncertain,
        ]
    );
}

#[test]
fn final_validation_panic_poisons_state() {
    let runtime = runtime(1);
    poison_after_admission(&runtime);
    assert!(matches!(
        runtime.reserve_process(key()),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
}

#[test]
fn witness_assignment_panic_poisons_state() {
    let runtime = runtime(1);
    let (_, receipt, pending, _) = reserved_pending(&runtime);
    let port = runtime.process_ledger_port();
    let guard = port
        .begin_admission(receipt.identity(), pending.admission_evidence())
        .unwrap();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _guard = guard;
            panic!("witness assignment fault");
        }))
        .is_err()
    );
    assert!(matches!(
        runtime.refund_process(receipt, ProcessRefundReason::Budget),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    assert!(matches!(
        runtime.reserve_process(key()),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
}

#[test]
fn commit_panic_poisons_state() {
    let runtime = runtime(1);
    let (_, receipt, pending, _) = reserved_pending(&runtime);
    let identity = receipt.identity();
    let port = runtime.process_ledger_port();
    let guard = port
        .begin_admission(identity.clone(), pending.admission_evidence())
        .unwrap();
    let mismatch = super::super::super::runtime::process_ledger::ProcessAdmissionEvidence::new(
        "invocation-1".to_owned(),
        [4; 32],
        [99; 32],
    );
    let (mut pending, validated) =
        pending_and_validated_with_evidence_override(identity.clone(), Some(mismatch));
    let token = pending.store_validated(validated, &identity);
    assert!(catch_unwind(AssertUnwindSafe(|| guard.commit(token))).is_err());
    assert!(matches!(
        runtime.refund_process(receipt, ProcessRefundReason::Budget),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    assert!(matches!(
        runtime.reserve_process(key()),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
}
