//! Cancellation races (Plan Task 10): idempotent receipt, fence of
//! late text after intent, terminal proof discipline, escalation and
//! restart-blocking behaviour across the adapter + journals.

mod common;

use common::{AllowPermit, SettlementPort, adapter, admit_model, call, dispatch_request};
use runne_provider_local::cancellation::{CancelPhase, CancellationJournal};
use runne_provider_local::port::{CancelDisposition, ProviderPort, Reconciliation};
use runne_provider_local::{ProviderError, RecoveryLedger};

fn dispatched() -> (
    tempfile::TempDir,
    runne_provider_local::LocalProviderAdapter<AllowPermit, SettlementPort>,
    runne_provider_local::PreparedRequest,
) {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare");
    a.dispatch(
        &prepared,
        &dispatch_request(&prepared.call_id, &fixture.artifact_digest),
    )
    .expect("dispatch");
    (dir, a, prepared)
}

/// The stream id handed out by `dispatch_request` in `dispatched()`.
const STREAM: [u8; 16] = [4; 16];

#[test]
fn double_cancel_gives_requested_then_already_requested() {
    let (_dir, mut a, _prepared) = dispatched();
    assert_eq!(
        a.cancel(&STREAM).expect("first"),
        CancelDisposition::Requested
    );
    assert_eq!(
        a.cancel(&STREAM).expect("second"),
        CancelDisposition::AlreadyRequested
    );
    assert!(a.cancelling(&STREAM));
}

#[test]
fn cancel_of_unknown_stream_is_frame_mismatch() {
    let (_dir, mut a, _prepared) = dispatched();
    let err = a.cancel(&[9; 16]).expect_err("unknown");
    assert!(matches!(err, ProviderError::FrameMismatch));
}

#[test]
fn terminal_stream_stays_settled_cancel_does_not_downgrade() {
    let (_dir, mut a, _prepared) = dispatched();
    assert_eq!(
        a.reconcile(&[2; 16]).expect("reconcile"),
        Reconciliation::Settled
    );
    let _ = a.cancel(&[4; 16]).expect("cancel");
    assert_eq!(
        a.reconcile(&[2; 16]).expect("reconcile"),
        Reconciliation::Settled
    );
}

#[test]
fn usage_settled_without_terminal_is_uncertain() {
    // The crash-matrix point "usage settled, crash before terminal":
    // mark settlement-only evidence and reconcile must NOT say Settled.
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    a.mark_dispatch_ambiguous([3; 16]);
    assert_eq!(
        a.reconcile(&[3; 16]).expect("reconcile"),
        Reconciliation::Uncertain
    );
}

#[test]
fn journal_gate_keeps_uncertain_from_reaching_completion() {
    let mut j = CancellationJournal::default();
    let mut ledger = RecoveryLedger::default();
    j.record_intent([5; 16], [6; 16]);
    j.record_signal([5; 16]).expect("signal");
    // Deadline hit without terminal proof:
    j.escalate_uncertain([5; 16]).expect("escalate");
    assert_eq!(
        j.state(&[5; 16]).unwrap().phase,
        CancelPhase::UncertainEscalated
    );
    ledger.absorb_cancel_phases(&[([5; 16], CancelPhase::UncertainEscalated)]);
    assert!(!ledger.can_admit_new_generation());
}
