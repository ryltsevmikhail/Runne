use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use super::post_fence::{WatcherTestControl, spawn_pre_fence_enrollment_owner_controlled};

#[tokio::test]
async fn work_cannot_start_before_watcher_claims_cleanup_ownership() {
    let work_started = Arc::new(AtomicUsize::new(0));
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let (claimed_tx, claimed_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let work_observed = Arc::clone(&work_started);
    let cleanup_observed = Arc::clone(&cleanup_calls);

    let (result, watcher) = spawn_pre_fence_enrollment_owner_controlled(
        move || async move {
            work_observed.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(())
        },
        move || async move {
            cleanup_observed.fetch_add(1, Ordering::SeqCst);
        },
        || (),
        WatcherTestControl::hold_after_claim(claimed_tx, release_rx),
    )
    .expect("watcher spawn");

    timeout(claimed_rx).await.expect("ownership claim");
    assert_eq!(work_started.load(Ordering::SeqCst), 0);
    release_tx.send(()).expect("release watcher");
    assert_eq!(result.await.expect("owner result"), Ok(()));
    timeout(watcher.wait()).await.expect("watcher completion");
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelled_work_is_failure_data_and_cleans_up_exactly_once() {
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let cleanup_observed = Arc::clone(&cleanup_calls);
    let (abort_tx, abort_rx) = tokio::sync::oneshot::channel();
    let (result, watcher) = spawn_pre_fence_enrollment_owner_controlled(
        || async {
            std::future::pending::<()>().await;
            Ok::<(), ()>(())
        },
        move || async move {
            cleanup_observed.fetch_add(1, Ordering::SeqCst);
        },
        || (),
        WatcherTestControl::observe_work(abort_tx),
    )
    .expect("watcher spawn");

    timeout(abort_rx).await.expect("work abort handle").abort();
    assert_eq!(result.await.expect("cancelled work result"), Err(()));
    timeout(watcher.wait()).await.expect("watcher completion");
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn watcher_spawn_failure_never_starts_work_or_cleanup() {
    let work_calls = Arc::new(AtomicUsize::new(0));
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let work_observed = Arc::clone(&work_calls);
    let cleanup_observed = Arc::clone(&cleanup_calls);

    let result = spawn_pre_fence_enrollment_owner_controlled(
        move || async move {
            work_observed.fetch_add(1, Ordering::SeqCst);
            Ok::<(), ()>(())
        },
        move || async move {
            cleanup_observed.fetch_add(1, Ordering::SeqCst);
        },
        || (),
        WatcherTestControl::fail_watcher_spawn(),
    );

    assert!(result.is_err());
    assert_eq!(work_calls.load(Ordering::SeqCst), 0);
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);
}

async fn timeout<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(1), future)
        .await
        .expect("watcher test timeout")
}
