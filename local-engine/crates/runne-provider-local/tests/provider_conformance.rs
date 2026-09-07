//! ProviderPort conformance: the same prepare determinism, capability
//! rejection, ordered stream, terminal usage and cancel cases run against
//! the LocalProviderAdapter with the fake host (Plan Task 8 Step 1).

mod common;

use common::{AllowPermit, SettlementPort, adapter, admit_model, call, dispatch_request};
use runne_provider_local::PreparedRequest;
use runne_provider_local::port::{ProviderPort, Reconciliation, StreamItem};

#[test]
fn prepare_is_deterministic() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let p1 = a.prepare(&c).expect("prepare 1");
    let p2 = a.prepare(&c).expect("prepare 2");
    assert_eq!(p1, p2);
    assert_eq!(p1.model_identity, "m1");
}

#[test]
fn prepare_rejects_unknown_manifest() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "x",
    );
    let err = a.prepare(&c).expect_err("unknown");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::ArtifactNotInstalled
    ));
}

#[test]
fn dispatch_streams_ordered_text_then_finish() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared: PreparedRequest = a.prepare(&c).expect("prepare");
    let stream = a
        .dispatch(
            &prepared,
            &dispatch_request(&prepared.call_id, &fixture.artifact_digest),
        )
        .expect("dispatch");
    assert!(stream.finished);
    let mut prev: Option<u64> = None;
    for item in &stream.items {
        if let StreamItem::Text { seq, .. } = item {
            if let Some(p) = prev {
                assert!(*seq > p, "stream order");
            }
            prev = Some(*seq);
        }
    }
}

#[test]
fn next_cursor_walks_stream() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare");
    let req = dispatch_request(&prepared.call_id, &fixture.artifact_digest);
    let stream = a.dispatch(&prepared, &req).expect("dispatch");
    let first = a.next(&stream.stream_id, 0).expect("next 0");
    assert!(first.is_some());
    let past = a.next(&stream.stream_id, u64::MAX).expect("next max");
    assert!(past.is_none(), "cursor past end → None after finish");
}

#[test]
fn reconcile_settled_after_terminal_stream() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare");
    let req = dispatch_request(&prepared.call_id, &fixture.artifact_digest);
    a.dispatch(&prepared, &req).expect("dispatch");
    assert_eq!(
        a.reconcile(&req.attempt_id).expect("reconcile"),
        Reconciliation::Settled
    );
}

#[test]
fn reconcile_absent_for_never_dispatched() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    assert_eq!(
        a.reconcile(&[9; 16]).expect("reconcile"),
        Reconciliation::Absent
    );
}

#[test]
fn cancel_known_stream_ok_unknown_rejected() {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let mut a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let c = call(&fixture.manifest_digest, "hello");
    let prepared = a.prepare(&c).expect("prepare");
    let req = dispatch_request(&prepared.call_id, &fixture.artifact_digest);
    let stream = a.dispatch(&prepared, &req).expect("dispatch");
    a.cancel(&stream.stream_id).expect("known");
    let err = a.cancel(&[9; 16]).expect_err("unknown");
    assert!(matches!(
        err,
        runne_provider_local::ProviderError::FrameMismatch
    ));
}
