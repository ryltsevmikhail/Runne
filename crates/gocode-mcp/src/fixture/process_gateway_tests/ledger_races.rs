use std::sync::{Arc, Barrier, mpsc};

use super::super::FixtureApprovalPolicy;
use super::super::runtime::process_ledger::{ProcessRefundReason, ProcessReserveOutcome};
use super::super::runtime_process_tests::routing::support::*;

#[test]
fn duplicate_reservation_has_one_owner_and_one_busy() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let (key, _) = key_payload(&fixture, "race-owner-busy");
    let barrier = Arc::new(Barrier::new(2));
    let (sender, receiver) = mpsc::sync_channel(2);
    let runtime = &fixture.runtime;
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let sender = sender.clone();
            let key = key.clone();
            scope.spawn(move || {
                barrier.wait();
                sender.send(runtime.reserve_process(key).unwrap()).unwrap();
            });
        }
    });
    let first = receiver.recv().unwrap();
    let second = receiver.recv().unwrap();
    assert!(matches!(
        (&first, &second),
        (
            ProcessReserveOutcome::Owner(_),
            ProcessReserveOutcome::BusyReserved
        ) | (
            ProcessReserveOutcome::BusyReserved,
            ProcessReserveOutcome::Owner(_)
        )
    ));
}

#[test]
fn old_refunded_receipt_is_blocked_after_retry_and_terminal() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let (key, _) = key_payload(&fixture, "race-stale-receipt");
    let first = match fixture.runtime.reserve_process(key.clone()).unwrap() {
        ProcessReserveOutcome::Owner(receipt) => receipt,
        _ => panic!("expected owner"),
    };
    let stale = fixture.runtime.duplicate_receipt_for_test(&first);
    fixture
        .runtime
        .refund_process(first, ProcessRefundReason::Budget)
        .unwrap();
    let retry = match fixture.runtime.reserve_process(key.clone()).unwrap() {
        ProcessReserveOutcome::Owner(receipt) => receipt,
        _ => panic!("expected retry owner"),
    };
    let (_, payload) = key_payload(&fixture, "race-stale-receipt");
    fixture
        .runtime
        .dispatch_reserved_process_gateway_for_test(retry, payload)
        .unwrap();
    assert!(
        fixture
            .runtime
            .refund_process(stale, ProcessRefundReason::Budget)
            .is_err()
    );
    assert!(matches!(
        fixture.runtime.reserve_process(key),
        Ok(ProcessReserveOutcome::TerminalReplay(_))
    ));
}
