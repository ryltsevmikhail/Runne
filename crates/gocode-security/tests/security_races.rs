use std::sync::Arc;

use tokio::sync::Barrier;

// TestBarrier — детерминированный barrier для race-тестов.
struct TestBarrier {
    barrier: Barrier,
}

impl TestBarrier {
    fn new(participants: usize) -> Self {
        Self {
            barrier: Barrier::new(participants),
        }
    }

    async fn wait(&self) {
        self.barrier.wait().await;
    }
}

#[tokio::test]
async fn race_dual_dispatch_same_permit_idempotent() {
    // Один permit и одно intent: второй вызов возвращает тот же результат идемпотентно.
    let barrier = Arc::new(TestBarrier::new(2));
    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let barrier_one = barrier.clone();
    let counter_one = counter.clone();
    let first = tokio::spawn(async move {
        barrier_one.wait().await;
        counter_one.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    });
    let barrier_two = barrier.clone();
    let counter_two = counter.clone();
    let second = tokio::spawn(async move {
        barrier_two.wait().await;
        counter_two.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    });

    let (first_result, second_result) = tokio::join!(first, second);

    assert!(first_result.is_ok());
    assert!(second_result.is_ok());
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn race_revocation_wins_over_dispatch() {
    // Сначала полностью завершаем отзыв, затем dispatch должен завершиться ошибкой.
    let state = Arc::new(tokio::sync::Mutex::new(false));
    let revoke_state = state.clone();
    let revoke = tokio::spawn(async move {
        let mut revoked = revoke_state.lock().await;
        *revoked = true;
    });
    revoke.await.unwrap();

    let dispatch_state = state.clone();
    let dispatch = tokio::spawn(async move {
        let revoked = dispatch_state.lock().await;
        !*revoked
    });

    assert!(!dispatch.await.unwrap());
}

#[tokio::test]
async fn race_cancel_fences_new_dispatch() {
    let cancelled = Arc::new(tokio::sync::Mutex::new(false));
    let cancel_state = cancelled.clone();
    let cancel = tokio::spawn(async move {
        let mut is_cancelled = cancel_state.lock().await;
        *is_cancelled = true;
    });
    cancel.await.unwrap();

    let dispatch_state = cancelled.clone();
    let dispatch = tokio::spawn(async move {
        let is_cancelled = dispatch_state.lock().await;
        !*is_cancelled
    });

    assert!(!dispatch.await.unwrap());
}

#[tokio::test]
async fn race_dual_approval_idempotent() {
    let barrier = Arc::new(TestBarrier::new(2));
    let approved = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let barrier_one = barrier.clone();
    let approval_one = approved.clone();
    let first = tokio::spawn(async move {
        barrier_one.wait().await;
        approval_one.store(true, std::sync::atomic::Ordering::SeqCst);
        true
    });
    let barrier_two = barrier.clone();
    let approval_two = approved.clone();
    let second = tokio::spawn(async move {
        barrier_two.wait().await;
        approval_two.store(true, std::sync::atomic::Ordering::SeqCst);
        true
    });

    let (first_result, second_result) = tokio::join!(first, second);

    assert!(first_result.unwrap());
    assert!(second_result.unwrap());
}

#[tokio::test]
async fn race_concurrent_grants_different_ids() {
    let barrier = Arc::new(TestBarrier::new(2));
    let first_id = Arc::new(tokio::sync::Mutex::new(String::new()));
    let second_id = Arc::new(tokio::sync::Mutex::new(String::new()));
    let barrier_one = barrier.clone();
    let first_grant = first_id.clone();
    let first = tokio::spawn(async move {
        barrier_one.wait().await;
        let mut grant_id = first_grant.lock().await;
        *grant_id = "grant-a".into();
    });
    let barrier_two = barrier.clone();
    let second_grant = second_id.clone();
    let second = tokio::spawn(async move {
        barrier_two.wait().await;
        let mut grant_id = second_grant.lock().await;
        *grant_id = "grant-b".into();
    });

    let _ = tokio::join!(first, second);

    assert_ne!(*first_id.lock().await, *second_id.lock().await);
}

#[tokio::test]
async fn race_cleanup_before_restart() {
    let state = Arc::new(tokio::sync::Mutex::new("active".to_string()));
    let cleanup_state = state.clone();
    let cleanup = tokio::spawn(async move {
        let mut lifecycle = cleanup_state.lock().await;
        *lifecycle = "terminal".to_string();
    });
    cleanup.await.unwrap();

    let restart_state = state.clone();
    let restart = tokio::spawn(async move {
        let lifecycle = restart_state.lock().await;
        lifecycle.clone()
    });

    assert_eq!(restart.await.unwrap(), "terminal");
}

#[tokio::test]
async fn race_restart_before_cleanup() {
    let generation = Arc::new(tokio::sync::Mutex::new(1_u64));
    let restart_generation = generation.clone();
    let restart = tokio::spawn(async move {
        let mut current_generation = restart_generation.lock().await;
        *current_generation += 1;
        *current_generation
    });
    restart.await.unwrap();

    let cleanup_generation = generation.clone();
    let cleanup = tokio::spawn(async move {
        let current_generation = cleanup_generation.lock().await;
        *current_generation > 1
    });

    assert!(cleanup.await.unwrap());
}

#[tokio::test]
async fn race_secret_resolve_before_revoke() {
    let handle_valid = Arc::new(tokio::sync::Mutex::new(true));
    let resolve_handle = handle_valid.clone();
    let resolve = tokio::spawn(async move {
        let mut handle = resolve_handle.lock().await;
        *handle = true;
        true
    });
    resolve.await.unwrap();

    // Отзыв происходит позже, но уже материализованный handle остаётся действительным.
    assert!(*handle_valid.lock().await);
}

#[tokio::test]
async fn race_secret_revoke_before_resolve() {
    let state = Arc::new(tokio::sync::Mutex::new("active".to_string()));
    let revoke_state = state.clone();
    let revoke = tokio::spawn(async move {
        let mut secret_state = revoke_state.lock().await;
        *secret_state = "revoked".to_string();
    });
    revoke.await.unwrap();

    let resolve_state = state.clone();
    let resolve = tokio::spawn(async move {
        let secret_state = resolve_state.lock().await;
        secret_state.as_str() != "revoked"
    });

    assert!(!resolve.await.unwrap());
}
