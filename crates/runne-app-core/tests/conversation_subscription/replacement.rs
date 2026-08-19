#[tokio::test]
async fn live_delivery_after_authenticated_context_replacement_is_closed_before_ack_or_ui() {
    let fixture = Fixture::opened().await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let subscription = fixture.subscribe(Arc::clone(&updates));
    fixture.runtime.wait_for_live(1).await;
    let acknowledged = fixture.runtime.ack_count();
    let lease = fixture
        .core
        .begin_bundled_runtime_restart()
        .await
        .expect("restart runtime");
    fixture
        .core
        .install_bundled_runtime_client(lease, fixture.runtime.protected_client())
        .await
        .expect("install replacement runtime");

    fixture.runtime.append_generation_failed();
    let error = tokio::time::timeout(Duration::from_secs(1), subscription)
        .await
        .expect("stale live delivery must close")
        .expect("subscription task")
        .expect_err("stale authenticated context");

    assert_eq!(error.to_string(), "runtime is unavailable");
    assert_eq!(fixture.runtime.ack_count(), acknowledged);
    assert!(updates.lock().expect("updates").is_empty());
}

#[tokio::test]
async fn replacement_waits_for_dispatch_and_following_reconciliation_under_one_operation_fence() {
    let fixture = Fixture::opened().await;
    fixture.runtime.block_generate();
    let core = Arc::clone(&fixture.core);
    let project_id = fixture.project_id;
    let send = tokio::spawn(async move { core.send_project_message(project_id, "hello").await });
    fixture.runtime.wait_for_generate(1).await;

    let core = Arc::clone(&fixture.core);
    let runtime = fixture.runtime.clone();
    let mut replace = tokio::spawn(async move {
        let lease = core.begin_bundled_runtime_restart().await?;
        core.install_bundled_runtime_client(lease, runtime.protected_client())
            .await
            .map(|_| ())
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut replace).await.is_err(),
        "replacement must not interleave dispatch with its authoritative replay"
    );

    fixture.runtime.release_generate();
    assert_eq!(
        send.await.expect("send task").expect("send snapshot").messages.len(),
        2
    );
    replace
        .await
        .expect("replacement task")
        .expect("replace after operation");
}

#[tokio::test]
async fn stale_terminal_cannot_change_the_replacement_runtime_state() {
    let fixture = Fixture::opened().await;
    let subscription = fixture.subscribe(Arc::new(Mutex::new(Vec::new())));
    fixture.runtime.wait_for_live(1).await;
    let lease = fixture
        .core
        .begin_bundled_runtime_restart()
        .await
        .expect("restart runtime");
    fixture
        .core
        .install_bundled_runtime_client(lease, fixture.runtime.protected_client())
        .await
        .expect("install replacement runtime");
    let replacement_state = fixture.core.bootstrap().expect("replacement state").runtime;
    fixture.runtime.terminal_live("replay_authorization_revoked");
    let error = tokio::time::timeout(Duration::from_secs(1), subscription)
        .await
        .expect("stale terminal must close")
        .expect("subscription task")
        .expect_err("stale terminal");

    assert_eq!(error.to_string(), "runtime is unavailable");
    assert_eq!(fixture.core.bootstrap().expect("replacement state").runtime, replacement_state);
}
