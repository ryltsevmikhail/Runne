#[tokio::test]
async fn completion_releases_the_exact_registry_record() {
    let manager = TaskRunSubscriptionManager::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let first = manager
        .subscribe(
            Arc::new(Source(Outcome::Complete)),
            TASK_RUN_ID,
            "main",
            recording_channel(Arc::clone(&events)),
        )
        .expect("subscribe");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while events.lock().expect("events lock").is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("initial update");
    manager.ack("main", &first, 1).expect("final delivery ACK");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while events.lock().expect("events lock").len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unexpected completion error");
    assert!(
        events
            .lock()
            .expect("events lock")
            .last()
            .is_some_and(|event| event.contains("task_run_subscription_unavailable")),
        "renderer receives a closed unexpected-completion error"
    );
    let next = wait_for_slot(&manager, Arc::new(Source(Outcome::Pending))).await;
    assert_ne!(first, next);
    manager.cancel("main", &next).await.expect("cancel");
}

#[tokio::test]
async fn source_error_releases_the_exact_registry_record() {
    let manager = TaskRunSubscriptionManager::new();
    let deliveries = Arc::new(AtomicUsize::new(0));
    let first = manager
        .subscribe(
            Arc::new(Source(Outcome::Error)),
            TASK_RUN_ID,
            "main",
            counting_channel(Arc::clone(&deliveries)),
        )
        .expect("subscribe");
    wait_for_deliveries(&deliveries, 1).await;
    manager.ack("main", &first, 1).expect("final delivery ACK");
    let next = wait_for_slot(&manager, Arc::new(Source(Outcome::Pending))).await;
    assert_ne!(first, next);
    manager.cancel("main", &next).await.expect("cancel");
}

#[tokio::test]
async fn source_resync_error_reaches_renderer_before_registry_cleanup() {
    let manager = TaskRunSubscriptionManager::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let first = manager
        .subscribe(
            Arc::new(Source(Outcome::Resync)),
            TASK_RUN_ID,
            "main",
            recording_channel(Arc::clone(&events)),
        )
        .expect("subscribe");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while events.lock().expect("events lock").is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("initial update");
    manager.ack("main", &first, 1).expect("final delivery ACK");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while events.lock().expect("events lock").len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal error");
    assert!(
        events
            .lock()
            .expect("events lock")
            .last()
            .is_some_and(|event| event.contains("replay_resync_required")),
        "renderer receives the typed terminal recovery"
    );
    let next = wait_for_slot(&manager, Arc::new(Source(Outcome::Pending))).await;
    manager.cancel("main", &next).await.expect("cancel");
}

#[tokio::test]
async fn immediate_cancellation_releases_slot_without_a_leaked_record() {
    let manager = TaskRunSubscriptionManager::new();
    let first = manager
        .subscribe(
            Arc::new(Source(Outcome::Pending)),
            TASK_RUN_ID,
            "main",
            channel(),
        )
        .expect("subscribe");
    manager
        .cancel("main", &first)
        .await
        .expect("cancel before source assignment can matter");
    let next = manager
        .subscribe(
            Arc::new(Source(Outcome::Pending)),
            TASK_RUN_ID,
            "main",
            channel(),
        )
        .expect("slot released");
    manager.cancel("main", &next).await.expect("cancel");
}

#[tokio::test]
async fn repeated_completion_cleanup_is_idempotent_and_preserves_slot_bounds() {
    let manager = TaskRunSubscriptionManager::new();
    for _ in 0..16 {
        let deliveries = Arc::new(AtomicUsize::new(0));
        let first = manager
            .subscribe(
                Arc::new(Source(Outcome::Complete)),
                TASK_RUN_ID,
                "main",
                counting_channel(Arc::clone(&deliveries)),
            )
            .expect("subscribe");
        wait_for_deliveries(&deliveries, 1).await;
        manager.ack("main", &first, 1).expect("final delivery ACK");
        let next = wait_for_slot(&manager, Arc::new(Source(Outcome::Pending))).await;
        manager.cancel("main", &next).await.expect("cancel");
    }
}
