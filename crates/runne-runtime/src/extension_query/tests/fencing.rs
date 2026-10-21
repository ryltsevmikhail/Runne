use super::super::*;
use super::fixtures::*;
use MetadataQueryError::*;
use std::sync::{Arc, Barrier};
// Breaks caught: missing fences, nonexclusive close, wrapping epoch, poison exposure.
#[test]
fn stale_snapshot_revision_and_digest_reject() {
    let o = capture(&json()).unwrap();
    for n in 0..2 {
        let mut r = request();
        if n == 0 {
            r.expected_snapshot.registration_revision = 8;
        } else {
            r.expected_snapshot.metadata_digest = [4; 32];
        }
        assert_eq!(o.query(r).unwrap_err(), StaleSnapshot);
    }
}
#[test]
fn stale_incarnation_generation_and_epoch_reject() {
    let o = capture(&json()).unwrap();
    for n in 0..3 {
        let mut r = request();
        match n {
            0 => r.context.runtime_incarnation = [3; 16],
            1 => r.context.runtime_generation = 2,
            _ => r.context.owner_epoch = 2,
        }
        assert_eq!(o.query(r).unwrap_err(), StaleGeneration);
    }
}
#[test]
fn close_fences_subsequent_reads() {
    let o = capture(&json()).unwrap();
    o.close(1).unwrap();
    assert_eq!(o.query(request()).unwrap_err(), OwnerClosed);
}
#[test]
fn wrong_expected_close_leaves_open_epoch_unchanged() {
    let o = capture(&json()).unwrap();
    assert_eq!(o.close(2), Err(StaleGeneration));
    assert_eq!(o.query(request()).unwrap().owner_epoch, 1);
}
#[test]
fn closed_close_any_expected_is_idempotent() {
    let o = capture(&json()).unwrap();
    o.close(1).unwrap();
    for e in [0, 1, 2, u64::MAX] {
        o.close(e).unwrap();
    }
    let s = o.state.read().unwrap();
    assert!(s.closed);
    assert_eq!(s.epoch, 2);
}
#[test]
fn owner_epoch_never_wraps_or_reopens() {
    let mut s = super::super::owner_state::OwnerState {
        epoch: i64::MAX as u64,
        closed: false,
    };
    assert_eq!(s.close(i64::MAX as u64), Err(InternalUnavailable));
    assert!(s.closed);
    assert_eq!(s.epoch, i64::MAX as u64);
}
#[test]
fn max_open_close_fences_then_returns_unavailable() {
    let o = capture(&json()).unwrap();
    o.state.write().unwrap().epoch = i64::MAX as u64;
    assert_eq!(o.close(i64::MAX as u64), Err(InternalUnavailable));
    assert_eq!(o.query(request()).unwrap_err(), OwnerClosed);
}
#[test]
fn repeat_after_max_close_is_ok() {
    let o = capture(&json()).unwrap();
    o.state.write().unwrap().epoch = i64::MAX as u64;
    assert_eq!(o.close(i64::MAX as u64), Err(InternalUnavailable));
    o.close(0).unwrap();
    assert_eq!(o.state.read().unwrap().epoch, i64::MAX as u64);
}
#[test]
fn epoch_cap_is_i64_max_not_u64_max() {
    let mut s = super::super::owner_state::OwnerState {
        epoch: i64::MAX as u64 - 1,
        closed: false,
    };
    s.close(i64::MAX as u64 - 1).unwrap();
    assert_eq!(s.epoch, i64::MAX as u64);
    let o = capture(&json()).unwrap();
    let mut r = request();
    r.context.owner_epoch = i64::MAX as u64 + 1;
    assert_eq!(o.query(r).unwrap_err(), InvalidRequest);
}
#[test]
fn poisoned_owner_lock_is_internal_unavailable() {
    let o = Arc::new(capture(&json()).unwrap());
    let other = o.clone();
    assert!(
        std::thread::spawn(move || {
            let _g = other.state.write().unwrap();
            panic!("controlled test poison");
        })
        .join()
        .is_err()
    );
    assert_eq!(o.query(request()).unwrap_err(), InternalUnavailable);
    assert_eq!(o.close(1), Err(InternalUnavailable));
}
#[test]
fn concurrent_read_close_has_one_linearization() {
    let o = Arc::new(capture(&json()).unwrap());
    let acquired = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let reader = o.clone();
    let a = acquired.clone();
    let b = release.clone();
    let read = std::thread::spawn(move || {
        let guard = reader.state.read().unwrap();
        let reply = reader.query_guarded(request(), &guard).unwrap();
        a.wait();
        b.wait();
        reply
    });
    acquired.wait();
    assert!(o.state.try_write().is_err());
    let closer = o.clone();
    let started = Arc::new(Barrier::new(2));
    let c = started.clone();
    let close = std::thread::spawn(move || {
        c.wait();
        closer.close(1)
    });
    started.wait();
    release.wait();
    assert_eq!(read.join().unwrap().records.len(), 4);
    close.join().unwrap().unwrap();
    assert_eq!(o.query(request()).unwrap_err(), OwnerClosed);
}
