use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use super::post_fence::{EnrollmentWatcher, spawn_pre_fence_enrollment_owner};

#[tokio::test]
async fn panic_while_constructing_transition_is_published_after_exact_cleanup() {
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&cleanup_calls);
    let (result, completion) = spawn_pre_fence_enrollment_owner(
        || {
            panic!("injected transition construction panic");
            #[allow(unreachable_code)]
            std::future::ready(Ok::<(), ()>(()))
        },
        move || async move {
            observed.fetch_add(1, Ordering::SeqCst);
        },
        || (),
    )
    .expect("watcher spawn");

    assert_eq!(result.await.expect("watcher publishes panic"), Err(()));
    await_watcher(completion).await;
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn panic_inside_async_transition_is_published_after_exact_cleanup() {
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&cleanup_calls);
    let (result, completion) = spawn_pre_fence_enrollment_owner(
        || async {
            tokio::task::yield_now().await;
            panic!("injected async transition panic");
            #[allow(unreachable_code)]
            Ok::<(), ()>(())
        },
        move || async move {
            observed.fetch_add(1, Ordering::SeqCst);
        },
        || (),
    )
    .expect("watcher spawn");

    assert_eq!(result.await.expect("watcher publishes panic"), Err(()));
    await_watcher(completion).await;
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dropped_result_receiver_never_cancels_owner_cleanup_or_completion() {
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&cleanup_calls);
    let (result, completion) = spawn_pre_fence_enrollment_owner(
        || async {
            tokio::task::yield_now().await;
            Err::<(), ()>(())
        },
        move || async move {
            observed.fetch_add(1, Ordering::SeqCst);
        },
        || (),
    )
    .expect("watcher spawn");
    drop(result);

    await_watcher(completion).await;
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exact_success_alone_disarms_outer_cleanup() {
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&cleanup_calls);
    let (result, completion) = spawn_pre_fence_enrollment_owner(
        || async { Ok::<_, ()>(7_u8) },
        move || async move {
            observed.fetch_add(1, Ordering::SeqCst);
        },
        || (),
    )
    .expect("watcher spawn");

    assert_eq!(result.await.expect("watcher result"), Ok(7));
    await_watcher(completion).await;
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cleanup_panic_is_observed_without_panicking_the_watcher() {
    let (result, watcher) = spawn_pre_fence_enrollment_owner(
        || async { Err::<(), ()>(()) },
        || async {
            panic!("injected cleanup panic");
        },
        || (),
    )
    .expect("watcher spawn");

    assert_eq!(result.await.expect("watcher publishes failure"), Err(()));
    await_watcher(watcher).await;
}

async fn await_watcher(watcher: EnrollmentWatcher) {
    tokio::time::timeout(Duration::from_secs(1), watcher.wait())
        .await
        .expect("watcher timeout")
        .expect("watcher terminated");
}
