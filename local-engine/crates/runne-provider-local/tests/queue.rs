//! Bounded queue (Plan Task 12 Step 4): finite capacity, scheduler-
//! owned order, one-loaded-model conflicts, no implicit eviction.

use runne_provider_local::error::ProviderError;
use runne_provider_local::queue::{BoundedDispatchQueue, QueueItem};

fn item(attempt: u8, model: &str) -> QueueItem {
    QueueItem {
        attempt_id: [attempt; 16],
        model_identity: model.into(),
    }
}

#[test]
fn full_queue_refuses() {
    let mut q = BoundedDispatchQueue::new(2);
    q.set_loaded_model("local:m1");
    q.push(item(1, "local:m1")).expect("1");
    q.push(item(2, "local:m1")).expect("2");
    let err = q.push(item(3, "local:m1")).expect_err("full");
    assert!(matches!(err, ProviderError::QueueFull));
    // Order is FIFO and preserved after the refusal.
    let first = q.pop().expect("pop").expect("item");
    assert_eq!(first.attempt_id, [1; 16]);
}

#[test]
fn different_model_conflicts_without_eviction() {
    let mut q = BoundedDispatchQueue::new(4);
    q.set_loaded_model("local:m1");
    q.push(item(1, "local:m1")).expect("same model");
    q.push(item(2, "local:m2")).expect("enqueue ok");
    // The same-model attempt drains normally.
    let same = q.pop().expect("pop").expect("item");
    assert_eq!(same.model_identity, "local:m1");
    // Now the head is for a DIFFERENT model: typed conflict, and the
    // item stays at the front — no implicit eviction or drop.
    let err = q.pop().expect_err("m2 head");
    assert!(matches!(err, ProviderError::OneLoadedModelConflict));
    assert_eq!(q.len(), 1);
}

#[test]
fn closed_queue_refuses_arrivals_but_drains() {
    let mut q = BoundedDispatchQueue::new(2);
    q.set_loaded_model("local:m1");
    q.push(item(1, "local:m1")).expect("before close");
    q.close();
    let err = q.push(item(2, "local:m1")).expect_err("closed");
    assert!(matches!(err, ProviderError::QueueClosed));
    assert!(q.pop().expect("drain").is_some());
    assert!(q.pop().expect("drain 2").is_none());
    assert!(q.drain_idle(), "idle after drain");
}
