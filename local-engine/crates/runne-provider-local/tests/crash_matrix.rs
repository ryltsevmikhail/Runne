//! Crash-point matrix (Plan Task 10 Step 1): every crash point maps to
//! exactly one reconciliation disposition and never to silent
//! redispatch or silent completion.

mod common;

use common::{AllowPermit, SettlementPort, adapter, admit_model, call, dispatch_request};
use runne_provider_local::port::{ProviderPort, Reconciliation};

fn fresh() -> (
    tempfile::TempDir,
    runne_provider_local::LocalProviderAdapter<AllowPermit, SettlementPort>,
) {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    (dir, a)
}

/// Point 1: crash BEFORE dispatch → Absent, nothing happened.
#[test]
fn crash_before_dispatch_is_absent() {
    let (_d, mut a) = fresh();
    assert_eq!(a.reconcile(&[1; 16]).expect("r"), Reconciliation::Absent);
}

/// Point 2: permit consumed / send lost — dispatch intent without any
/// terminal evidence → Uncertain (coordinator records the ambiguity).
#[test]
fn crash_after_send_before_ack_is_uncertain() {
    let (_d, mut a) = fresh();
    a.mark_dispatch_ambiguous([2; 16]);
    assert_eq!(a.reconcile(&[2; 16]).expect("r"), Reconciliation::Uncertain);
}

/// Point 3: full dispatch — terminal item present → Settled exactly
/// once; repeated reconciliation is stable.
#[test]
fn crash_after_terminal_is_settled_and_stable() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare");
    let req = dispatch_request(&prepared.call_id, &fixture.artifact_digest);
    a.dispatch(&prepared, &req).expect("dispatch");
    for _ in 0..3 {
        assert_eq!(
            a.reconcile(&req.attempt_id).expect("r"),
            Reconciliation::Settled
        );
    }
}

/// Point 4: replay of a settled attempt conflicts — never re-executes.
#[test]
fn settled_attempt_replay_conflicts() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare");
    let req = dispatch_request(&prepared.call_id, &fixture.artifact_digest);
    a.dispatch(&prepared, &req).expect("dispatch");
    let err = a
        .dispatch(&prepared, &req)
        .expect_err("replay after terminal");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::AttemptConflict
    ));
}

/// Point 5: unknown attempt → Absent (never fabricated evidence).
#[test]
fn unknown_attempt_after_other_activity_is_absent() {
    let (_d, mut a) = fresh();
    a.mark_dispatch_ambiguous([2; 16]);
    assert_eq!(a.reconcile(&[8; 16]).expect("r"), Reconciliation::Absent);
}
