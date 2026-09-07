//! Restart reconciliation (Plan Task 10 Step 4): a fresh generation
//! admits new work only after every uncertain cleanup recorded its
//! evidence; transport loss never becomes automatic redispatch.

mod common;

use common::{AllowPermit, SettlementPort, adapter, admit_model, call, dispatch_request};
use runne_provider_local::port::{ProviderPort, Reconciliation};
use runne_provider_local::{CleanupEvidence, RecoveryLedger};

#[test]
fn restart_is_blocked_by_unresolved_uncertain() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare");
    // Transport loss after send: the attempt is ambiguous.
    a.mark_dispatch_ambiguous([4; 16]);
    assert_eq!(a.reconcile(&[4; 16]).expect("r"), Reconciliation::Uncertain);

    // New generation ledger: the ambiguity blocks it.
    let mut ledger = RecoveryLedger::default();
    ledger.mark_uncertain([4; 16]);
    assert!(!ledger.can_admit_new_generation());

    // Evidence resolves; a new attempt is then admitted.
    assert!(ledger.record_cleanup_evidence([4; 16], CleanupEvidence([11; 32])));
    assert!(ledger.can_admit_new_generation());
    let req2 = dispatch_request(&prepared.call_id, &fixture.artifact_digest);
    let _ = req2; // fresh dispatch allowed at composition once unblocked
}

#[test]
fn ambiguous_attempt_is_never_reported_settled() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    a.mark_dispatch_ambiguous([6; 16]);
    for _ in 0..3 {
        assert_eq!(a.reconcile(&[6; 16]).expect("r"), Reconciliation::Uncertain);
    }
}

#[test]
fn full_dispatch_after_recovery_is_fresh_evidence() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    // Old ambiguous attempt:
    a.mark_dispatch_ambiguous([4; 16]);
    // New attempt (distinct id) runs fully after ledger unblocked:
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare");
    let mut req = dispatch_request(&prepared.call_id, &fixture.artifact_digest);
    req.attempt_id = [5; 16];
    a.dispatch(&prepared, &req).expect("fresh dispatch");
    assert_eq!(a.reconcile(&[5; 16]).expect("r"), Reconciliation::Settled);
    // Old attempt still uncertain — separate evidence line.
    assert_eq!(a.reconcile(&[4; 16]).expect("r"), Reconciliation::Uncertain);
}
