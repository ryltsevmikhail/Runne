use super::super::super::runtime::process_ledger::{
    ProcessPhaseOutcome, ProcessRefundReason, ProcessReserveOutcome, ProcessUncertainReason,
};
use super::super::super::{FixtureCallResult, FixtureMcpFailure};
use super::support::*;

#[test]
fn duplicate_reserve_has_one_owner_and_one_busy_without_second_receipt() {
    let runtime = runtime(1);
    let owner = owner(&runtime, key());
    assert!(matches!(
        runtime.reserve_process(key()).unwrap(),
        ProcessReserveOutcome::BusyReserved
    ));
    assert_eq!(runtime.accounting_remaining(), 0);
    assert_eq!(runtime.audit().len(), 1);
    assert_eq!(owner.identity().attempt_for_test(), 1);
}

#[test]
fn every_key_field_conflict_is_rejected() {
    let runtime = runtime(2);
    let _owner = owner(&runtime, key());
    for field in [1, 2, 3, 5, 6, 7, 8, 9, 10] {
        assert!(matches!(
            runtime.reserve_process(key_with(field)).unwrap(),
            ProcessReserveOutcome::InvocationConflict
        ));
    }
    assert!(matches!(
        runtime.reserve_process(key_with(4)).unwrap(),
        ProcessReserveOutcome::Owner(_)
    ));
    assert_eq!(runtime.accounting_remaining(), 0);
}

#[test]
fn refunded_current_entry_is_retained() {
    let runtime = runtime(1);
    let receipt = owner(&runtime, key());
    runtime
        .refund_process(receipt, ProcessRefundReason::Budget)
        .unwrap();
    let retry = owner(&runtime, key());
    assert_eq!(retry.identity().attempt_for_test(), 2);
    assert_eq!(runtime.accounting_remaining(), 0);
    assert_eq!(
        runtime
            .audit()
            .iter()
            .map(|record| record.process_phase())
            .collect::<Vec<_>>(),
        vec![
            Some(super::super::super::FixtureAuditProcessPhase::Reserved),
            Some(super::super::super::FixtureAuditProcessPhase::Refunded),
            Some(super::super::super::FixtureAuditProcessPhase::Reserved)
        ]
    );
}

#[test]
fn old_receipt_cannot_refund_or_admit_after_retry() {
    let runtime = runtime(1);
    let receipt = owner(&runtime, key());
    let stale = receipt.identity();
    runtime
        .refund_process(receipt, ProcessRefundReason::Budget)
        .unwrap();
    let _retry = owner(&runtime, key());
    assert!(matches!(
        runtime.refund_process(
            runtime.receipt_for_test(stale.clone()),
            ProcessRefundReason::Budget
        ),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    let (pending, _) = pending_and_validated(stale.clone());
    assert!(matches!(
        runtime
            .process_ledger_port()
            .begin_admission(stale, pending.admission_evidence()),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
}

#[test]
fn old_receipt_cannot_refund_or_admit_after_terminal_state() {
    let runtime = runtime(1);
    let (_key, receipt, pending) = admit(&runtime);
    let stale = receipt.identity();
    assert!(matches!(
        runtime
            .process_ledger_port()
            .settle_completed(receipt, pending),
        ProcessPhaseOutcome::EffectCompleted { .. }
    ));
    assert!(matches!(
        runtime.refund_process(
            runtime.receipt_for_test(stale.clone()),
            ProcessRefundReason::Budget
        ),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    let (pending, _) = pending_and_validated(stale.clone());
    assert!(matches!(
        runtime
            .process_ledger_port()
            .begin_admission(stale, pending.admission_evidence()),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
}

#[test]
fn overflow_is_atomic() {
    let runtime = runtime(1);
    let receipt = owner(&runtime, key());
    runtime
        .refund_process(receipt, ProcessRefundReason::Budget)
        .unwrap();
    runtime.set_attempt_for_test("raw-invocation-sentinel", u64::MAX);
    let before = (runtime.accounting_remaining(), runtime.audit());
    assert!(matches!(
        runtime.reserve_process(key()),
        Err(FixtureMcpFailure::AccountingMismatch)
    ));
    assert_eq!((runtime.accounting_remaining(), runtime.audit()), before);
}

#[test]
fn completed_and_uncertain_are_first_wins() {
    let runtime = runtime(1);
    let (key, receipt, pending) = admit(&runtime);
    let other = runtime.duplicate_receipt_for_test(&receipt);
    let barrier = std::sync::Barrier::new(2);
    let ledger = runtime.process_ledger_port();
    let completed_port = ledger.clone();
    let uncertain_port = ledger.clone();
    let (completed, replayed) = std::thread::scope(|scope| {
        let completed = scope.spawn(|| {
            barrier.wait();
            completed_port.settle_completed(receipt, pending)
        });
        let replayed = scope.spawn(|| {
            barrier.wait();
            uncertain_port.settle_uncertain(other, ProcessUncertainReason::Host)
        });
        (completed.join().unwrap(), replayed.join().unwrap())
    });
    assert!(matches!(
        (&completed, &replayed),
        (
            ProcessPhaseOutcome::EffectCompleted { .. },
            ProcessPhaseOutcome::EffectCompleted { .. }
        ) | (
            ProcessPhaseOutcome::EffectUncertain { .. },
            ProcessPhaseOutcome::EffectUncertain { .. }
        )
    ));
    let replay = runtime.reserve_process(key).unwrap();
    assert!(matches!(
        replay,
        ProcessReserveOutcome::TerminalReplay(
            FixtureCallResult::Completed | FixtureCallResult::Uncertain
        )
    ));
}
