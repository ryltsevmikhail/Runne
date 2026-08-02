#[test]
fn timeline_update_serializes_only_sanitized_projection_data() {
    let update = ConversationTimelineUpdate {
        conversation_id: "018f2e3a-7000-7000-8000-000000000110".to_owned(),
        projection_revision: 7,
        stream_version: 9,
        message: Some(ConversationMessageSummary {
            message_id: "018f2e3a-7000-7000-8000-000000000115".to_owned(),
            role: "assistant".to_owned(),
            task_run_id: "018f2e3a-7000-7000-8000-000000000113".to_owned(),
            attempt_id: "018f2e3a-7000-7000-8000-000000000114".to_owned(),
            text: "bounded text".to_owned(),
            committed_at: 1_722_330_000_000_000,
        }),
        recovery: ConversationRecoveryDisposition::Live,
    };

    let value = serde_json::to_value(update).expect("serialize update");
    let object = value.as_object().expect("object");
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "conversationId",
            "message",
            "projectionRevision",
            "recovery",
            "streamVersion",
        ]
    );
    let encoded = serde_json::to_string(object).expect("encode");
    for forbidden in [
        "cursor",
        "binding",
        "token",
        "endpoint",
        "secret",
        "authority",
        "session",
        "certificate",
        "credential",
    ] {
        assert!(!encoded.to_ascii_lowercase().contains(forbidden));
    }
}

#[tokio::test]
async fn inclusive_duplicate_is_acknowledged_without_ui_update() {
    let fixture = Fixture::opened().await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let acknowledged_before = fixture.runtime.ack_count();
    let subscription = fixture.subscribe(Arc::clone(&updates));

    fixture.runtime.wait_for_live(1).await;
    assert_eq!(fixture.runtime.ack_count(), acknowledged_before + 1);
    assert!(updates.lock().expect("updates").is_empty());
    subscription.abort();
}

#[tokio::test]
async fn disconnect_after_ack_uses_fresh_catch_up_and_recovers_without_duplicates() {
    let fixture = Fixture::opened().await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let subscription = fixture.subscribe(Arc::clone(&updates));
    fixture.runtime.wait_for_live(1).await;
    fixture.runtime.append_generation_failed();
    let acknowledged_after_first = fixture.runtime.ack_count() + 1;
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.runtime.ack_count() < acknowledged_after_first {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first live event acknowledged");
    let open_before_disconnect = fixture.runtime.open_count();

    fixture.runtime.disconnect_live();
    fixture.runtime.append_generation_failed();
    tokio::time::timeout(
        Duration::from_secs(2),
        fixture.runtime.wait_for_open(open_before_disconnect + 1),
    )
    .await
    .expect("fresh replay session opened from committed checkpoint");
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.runtime.ack_count() < acknowledged_after_first + 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("inclusive duplicate and new event acknowledged");

    let snapshot = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect("automatic recovery remains live");
    assert_eq!(snapshot.messages.len(), 0);
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Live
    );
    subscription.abort();
}

#[tokio::test]
async fn explicit_resync_resets_only_the_affected_scope_and_rebuilds_from_floor() {
    let fixture = Fixture::opened().await;
    fixture.runtime.force_retention_gap_once();
    let error = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("persisted cursor is outside retention");
    assert_eq!(error.to_string(), "replay_resync_required");
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::ResyncRequired
    );
    let create_before = fixture.runtime.create_count();

    let snapshot = fixture
        .core
        .resync_project_conversation(fixture.project_id)
        .await
        .expect("dedicated resync rebuild");

    assert_eq!(snapshot.messages.len(), 0);
    assert_eq!(fixture.runtime.create_count(), create_before);
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Live
    );
}

#[tokio::test]
async fn explicit_resync_rejects_unaffected_project_scope_without_resetting_it() {
    let fixture = Fixture::opened().await;
    let other_project_path = fixture.directory.path().join("other-project");
    std::fs::create_dir(&other_project_path).expect("other project");
    let other_project_id = fixture
        .core
        .open_local_project(&other_project_path)
        .expect("open other project")
        .id;
    fixture
        .core
        .open_project_conversation(other_project_id)
        .await
        .expect("bind other project conversation");
    fixture.runtime.force_retention_gap_once();
    let error = fixture
        .core
        .open_project_conversation(other_project_id)
        .await
        .expect_err("other project requires resync");
    assert_eq!(error.to_string(), "replay_resync_required");

    let wrong_scope = fixture
        .core
        .resync_project_conversation(fixture.project_id)
        .await
        .expect_err("unaffected project cannot claim resync");

    assert_eq!(wrong_scope.to_string(), "replay_resync_required");
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::ResyncRequired
    );
    let snapshot = fixture
        .core
        .resync_project_conversation(other_project_id)
        .await
        .expect("affected project remains retryable and rebuilds");
    assert_eq!(snapshot.messages.len(), 0);
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Live
    );
}

#[tokio::test]
async fn explicit_resync_remains_retryable_after_transient_rebuild_failure() {
    let fixture = Fixture::opened().await;
    fixture.runtime.force_retention_gap_once();
    let error = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("persisted cursor is outside retention");
    assert_eq!(error.to_string(), "replay_resync_required");

    fixture.runtime.fail_next_open_with_reconnectable_error();
    let transient = fixture
        .core
        .resync_project_conversation(fixture.project_id)
        .await
        .expect_err("transient rebuild failure");

    assert_eq!(transient.to_string(), "runtime is unavailable");
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::ResyncRequired
    );
    let snapshot = fixture
        .core
        .resync_project_conversation(fixture.project_id)
        .await
        .expect("resync can be retried after transient failure");
    assert_eq!(snapshot.messages.len(), 0);
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Live
    );
}

#[tokio::test]
async fn pending_resync_scope_survives_unrelated_live_reconnect_state() {
    let fixture = Fixture::opened().await;
    let other_project_path = fixture.directory.path().join("project-with-gap");
    std::fs::create_dir(&other_project_path).expect("other project");
    let other_project_id = fixture
        .core
        .open_local_project(&other_project_path)
        .expect("open other project")
        .id;
    fixture
        .core
        .open_project_conversation(other_project_id)
        .await
        .expect("bind other project");
    fixture.runtime.force_retention_gap_once();
    let error = fixture
        .core
        .open_project_conversation(other_project_id)
        .await
        .expect_err("other project requires resync");
    assert_eq!(error.to_string(), "replay_resync_required");

    fixture
        .core
        .force_runtime_reconnecting_for_test()
        .expect("simulate unrelated raw reconnect transition");

    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::ResyncRequired
    );
    let snapshot = fixture
        .core
        .resync_project_conversation(other_project_id)
        .await
        .expect("resync scope remains authoritative after unrelated reconnect");
    assert_eq!(snapshot.messages.len(), 0);
}
