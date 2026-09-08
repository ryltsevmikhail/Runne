#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_waits_for_blocked_source_termination_before_slot_reuse() {
    let manager = Arc::new(TaskRunSubscriptionManager::new());
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let terminated = Arc::new(AtomicBool::new(false));
    let first = manager
        .subscribe(
            Arc::new(BlockingSource {
                started: Mutex::new(Some(started_tx)),
                release: Mutex::new(Some(release_rx)),
                terminated: Arc::clone(&terminated),
            }),
            TASK_RUN_ID,
            "main",
            channel(),
        )
        .expect("subscribe");
    started_rx.await.expect("source started");
    let cancellation = manager.cancel("main", &first);
    tokio::pin!(cancellation);
    tokio::select! {
        result = &mut cancellation => panic!("cancellation completed early: {result:?}"),
        () = tokio::task::yield_now() => {}
    }
    assert!(
        manager
            .subscribe(
                Arc::new(Source(Outcome::Pending)),
                TASK_RUN_ID,
                "main",
                channel()
            )
            .is_err(),
        "slot stays reserved while source is blocked"
    );
    release_tx.send(()).expect("release source");
    cancellation.await.expect("confirmed cancellation");
    assert!(terminated.load(Ordering::Acquire), "source was terminated");
    let next = manager
        .subscribe(
            Arc::new(Source(Outcome::Pending)),
            TASK_RUN_ID,
            "main",
            channel(),
        )
        .expect("slot released after join");
    manager.cancel("main", &next).await.expect("cancel");
}

#[tokio::test]
async fn slow_renderer_receives_one_in_flight_update_until_its_exact_ack() {
    let manager = TaskRunSubscriptionManager::new();
    let deliveries = Arc::new(AtomicUsize::new(0));
    let id = manager
        .subscribe(
            Arc::new(BurstSource {
                updates: 2,
                pending: true,
            }),
            TASK_RUN_ID,
            "main",
            counting_channel(Arc::clone(&deliveries)),
        )
        .expect("subscribe");
    wait_for_deliveries(&deliveries, 1).await;
    tokio::task::yield_now().await;
    assert_eq!(deliveries.load(Ordering::Acquire), 1);
    manager.ack("main", &id, 1).expect("exact first ACK");
    wait_for_deliveries(&deliveries, 2).await;
    manager.cancel("main", &id).await.expect("cancel");
}

#[tokio::test]
async fn duplicate_or_out_of_order_ack_closes_the_exact_subscription() {
    let manager = TaskRunSubscriptionManager::new();
    let deliveries = Arc::new(AtomicUsize::new(0));
    let id = manager
        .subscribe(
            Arc::new(BurstSource {
                updates: 1,
                pending: true,
            }),
            TASK_RUN_ID,
            "main",
            counting_channel(Arc::clone(&deliveries)),
        )
        .expect("subscribe");
    wait_for_deliveries(&deliveries, 1).await;
    assert!(
        manager.ack("main", &id, 2).is_err(),
        "future ACK is rejected"
    );
    let duplicate_deliveries = Arc::new(AtomicUsize::new(0));
    let duplicate = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Ok(id) = manager.subscribe(
                Arc::new(BurstSource {
                    updates: 1,
                    pending: true,
                }),
                TASK_RUN_ID,
                "main",
                counting_channel(Arc::clone(&duplicate_deliveries)),
            ) {
                return id;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed ACK cleanup");
    wait_for_deliveries(&duplicate_deliveries, 1).await;
    manager.ack("main", &duplicate, 1).expect("exact ACK");
    assert!(
        manager.ack("main", &duplicate, 1).is_err(),
        "duplicate ACK is rejected"
    );
    let next = wait_for_slot(&manager, Arc::new(Source(Outcome::Pending))).await;
    manager.cancel("main", &next).await.expect("cancel");
}

#[tokio::test]
async fn queue_overflow_stops_delivery_and_releases_the_subscription_slot() {
    let manager = TaskRunSubscriptionManager::new();
    let deliveries = Arc::new(AtomicUsize::new(0));
    let _ = manager
        .subscribe(
            Arc::new(BurstSource {
                updates: 65,
                pending: false,
            }),
            TASK_RUN_ID,
            "main",
            counting_channel(Arc::clone(&deliveries)),
        )
        .expect("subscribe");
    wait_for_deliveries(&deliveries, 1).await;
    tokio::task::yield_now().await;
    assert!(
        deliveries.load(Ordering::Acquire) <= 2,
        "bounded delivery window"
    );
    let next = wait_for_slot(&manager, Arc::new(Source(Outcome::Pending))).await;
    manager.cancel("main", &next).await.expect("cancel");
}
