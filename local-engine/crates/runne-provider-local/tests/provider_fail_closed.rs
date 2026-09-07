//! Fail-closed tests: unadmitted permit, attempt replay conflict,
//! foreign prepared call, reconciliation uncertainty after ambiguous
//! dispatch acknowledgement.

mod common;

use common::{
    AllowPermit, DenyPermit, SettlementPort, adapter, admit_model, call, dispatch_request,
};
use runne_provider_local::ProviderError;
use runne_provider_local::port::{ProviderPort, Reconciliation};

#[test]
fn unadmitted_permit_blocks_dispatch() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), DenyPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare is effect-free");
    let req = dispatch_request(&prepared.call_id, &fixture.artifact_digest);
    let err = a.dispatch(&prepared, &req).expect_err("deny");
    assert!(matches!(err, ProviderError::FrameMismatch));
    assert_eq!(
        a.reconcile(&req.attempt_id).expect("reconcile"),
        Reconciliation::Absent
    );
}

#[test]
fn attempt_replay_conflicts() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare");
    let req = dispatch_request(&prepared.call_id, &fixture.artifact_digest);
    a.dispatch(&prepared, &req).expect("first dispatch");
    let err = a
        .dispatch(&prepared, &req)
        .expect_err("replay of the same attempt");
    assert!(matches!(err, ProviderError::AttemptConflict));
}

#[test]
fn foreign_prepared_call_rejected() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare");
    let mut req = dispatch_request(&prepared.call_id, &fixture.artifact_digest);
    req.prepared_call_id = [7; 16]; // foreign call id
    let err = a.dispatch(&prepared, &req).expect_err("foreign");
    assert!(matches!(err, ProviderError::FrameMismatch));
    // Attempt stays absent (no effect happened).
    assert_eq!(
        a.reconcile(&req.attempt_id).expect("reconcile"),
        Reconciliation::Absent
    );
}

#[test]
fn ambiguous_dispatch_marks_uncertain() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    a.mark_dispatch_ambiguous([8; 16]);
    assert_eq!(
        a.reconcile(&[8; 16]).expect("reconcile"),
        Reconciliation::Uncertain
    );
}
