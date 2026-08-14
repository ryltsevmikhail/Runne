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
async fn retention_gap_does_not_arm_public_resync_or_reset_affected_scope() {
    let fixture = Fixture::opened().await;
    fixture.runtime.force_retention_gap_once();
    let opens_before = fixture.runtime.open_count();
    let error = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("persisted cursor is outside retention");
    assert_eq!(error.to_string(), "runtime_incompatible");
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Incompatible
    );
    let resync = fixture
        .core
        .resync_project_conversation(fixture.project_id)
        .await
        .expect_err("Task 10 does not promote a retention baseline to reset authority");
    assert_eq!(resync.to_string(), "runtime is unavailable");
    assert_eq!(fixture.runtime.open_count(), opens_before + 1);
}

#[tokio::test]
async fn retention_gap_does_not_grant_resync_to_another_scope() {
    let fixture = Fixture::opened().await;
    let other_project_path = fixture.directory.path().join("other-project");
    std::fs::create_dir(&other_project_path).expect("other project");
    let other_project_id = fixture
        .core
        .open_local_project(&other_project_path)
        .expect("open other project");
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
        .expect_err("other project must fail closed");
    assert_eq!(error.to_string(), "runtime_incompatible");

    let wrong_scope = fixture
        .core
        .resync_project_conversation(fixture.project_id)
        .await
        .expect_err("unaffected project cannot claim reset authority");

    assert_eq!(wrong_scope.to_string(), "runtime is unavailable");
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Incompatible
    );
    let affected_scope = fixture
        .core
        .resync_project_conversation(other_project_id)
        .await
        .expect_err("affected project cannot reset until Task 11");
    assert_eq!(affected_scope.to_string(), "runtime is unavailable");
}

#[tokio::test]
async fn retention_gap_resync_request_does_not_trigger_transient_rebuild() {
    let fixture = Fixture::opened().await;
    fixture.runtime.force_retention_gap_once();
    let error = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("persisted cursor is outside retention");
    assert_eq!(error.to_string(), "runtime_incompatible");

    fixture.runtime.fail_next_open_with_reconnectable_error();
    let opens_before_resync = fixture.runtime.open_count();
    let rejected = fixture
        .core
        .resync_project_conversation(fixture.project_id)
        .await
        .expect_err("resync must remain unavailable before any rebuild request");

    assert_eq!(rejected.to_string(), "runtime is unavailable");
    assert_eq!(fixture.runtime.open_count(), opens_before_resync);
}

#[tokio::test]
async fn retention_gap_stays_closed_after_another_scope_was_opened() {
    let fixture = Fixture::opened().await;
    let other_project_path = fixture.directory.path().join("project-with-gap");
    std::fs::create_dir(&other_project_path).expect("other project");
    let other_project_id = fixture
        .core
        .open_local_project(&other_project_path)
        .expect("open other project");
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
        .expect_err("other project must fail closed");
    assert_eq!(error.to_string(), "runtime_incompatible");

    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Incompatible
    );
    let resync = fixture
        .core
        .resync_project_conversation(other_project_id)
        .await
        .expect_err("existing local scope does not authorize a reset");
    assert_eq!(resync.to_string(), "runtime is unavailable");
}
