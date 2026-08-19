#[tokio::test]
async fn mutation_remains_live_while_subscription_reconcile_waits_and_race_applies_once() {
    let fixture = Fixture::opened().await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let primary_subscription = fixture.subscribe(Arc::clone(&updates));
    fixture.runtime.wait_for_live(1).await;
    fixture.runtime.block_generate();
    let core = Arc::clone(&fixture.core);
    let project_id = fixture.project_id;
    let send = tokio::spawn(async move { core.send_project_message(project_id, "hello").await });
    fixture.runtime.wait_for_generate(1).await;
    let open_before = fixture.runtime.open_count();
    let second_updates = Arc::new(Mutex::new(Vec::new()));
    let second_subscription = fixture.subscribe(second_updates);

    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            fixture.runtime.wait_for_open(open_before + 1)
        )
        .await
        .is_err(),
        "reconciliation must wait for the in-flight mutation lease"
    );
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Live
    );

    fixture.runtime.release_generate();
    let sent_snapshot = send.await.expect("send task").expect("send and reconcile");
    assert_eq!(sent_snapshot.messages.len(), 2);
    fixture.runtime.wait_for_open(open_before + 2).await;
    fixture.runtime.wait_for_live(2).await;

    let restored = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect("restore projection");
    assert_eq!(restored.messages.len(), 2);
    let updates = updates.lock().expect("updates");
    let message_ids = updates
        .iter()
        .filter_map(|update| update.message.as_ref())
        .map(|message| message.message_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        message_ids.iter().copied().collect::<HashSet<_>>().len(),
        message_ids.len()
    );
    assert!(message_ids.len() <= 2);
    drop(updates);
    primary_subscription.abort();
    second_subscription.abort();
}
