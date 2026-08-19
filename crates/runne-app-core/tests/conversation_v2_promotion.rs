mod support;

#[tokio::test]
async fn authenticated_v2_baseline_promotes_before_live_activation() {
    let fixture = support::Fixture::opened().await;
    let opens_before = fixture.runtime.open_count();
    let acks_before = fixture.runtime.ack_count();

    fixture.runtime.force_retention_v2_gap_once();
    let snapshot = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect("V2 promotion");

    assert_eq!(snapshot.stream_version, 3);
    assert_eq!(snapshot.messages.len(), 1);
    assert_eq!(snapshot.messages[0].text, "promoted historical text");
    assert_eq!(snapshot.messages[0].committed_at, 1_722_330_000_000_002);
    assert_eq!(fixture.runtime.open_count(), opens_before + 1);
    assert_eq!(fixture.runtime.ack_count(), acks_before + 1);
    assert_eq!(
        fixture.core.bootstrap().expect("bootstrap").runtime,
        runne_app_core::RuntimeAvailability::Live
    );
}

#[tokio::test]
async fn failed_shadow_commit_keeps_old_projection_and_sends_no_ack() {
    let fixture = support::Fixture::opened().await;
    let acks_before = fixture.runtime.ack_count();
    let connection = rusqlite::Connection::open(&fixture.database_path).expect("database");
    connection.execute_batch("CREATE TRIGGER fail_shadow BEFORE INSERT ON replay_shadow_events BEGIN SELECT RAISE(FAIL, 'forced'); END;").expect("trigger");

    fixture.runtime.force_retention_v2_gap_once();
    let error = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("local shadow failure");

    assert_eq!(error.to_string(), "local_projection_unavailable");
    assert_eq!(fixture.runtime.ack_count(), acks_before);
    let sequence: i64 = connection
        .query_row("SELECT event_sequence FROM replay_cursors", [], |row| {
            row.get(0)
        })
        .expect("old active checkpoint");
    assert_eq!(sequence, 1);
    connection
        .execute_batch("DROP TRIGGER fail_shadow;")
        .expect("remove failure trigger");
    drop(connection);

    let reopened = fixture.reopen().await;
    fixture.runtime.force_retention_v2_gap_once();
    let snapshot = reopened
        .open_project_conversation(fixture.project_id)
        .await
        .expect("reopen recovers pending shadow");
    assert_eq!(snapshot.stream_version, 3);
    assert_eq!(fixture.runtime.ack_count(), acks_before + 1);
}

#[tokio::test]
async fn cancelled_v2_resume_keeps_active_projection_until_a_reopened_retry() {
    let fixture = support::Fixture::opened().await;
    let acks_before = fixture.runtime.ack_count();
    fixture.runtime.block_v2_resume();
    fixture.runtime.force_retention_v2_gap_once();
    let core = std::sync::Arc::clone(&fixture.core);
    let project_id = fixture.project_id;
    let operation = tokio::spawn(async move { core.open_project_conversation(project_id).await });

    fixture.runtime.wait_for_v2_resume(1).await;
    let connection = rusqlite::Connection::open(&fixture.database_path).expect("database");
    let sequence: i64 = connection
        .query_row("SELECT event_sequence FROM replay_cursors", [], |row| {
            row.get(0)
        })
        .expect("old active checkpoint");
    assert_eq!(sequence, 1);
    assert_eq!(fixture.runtime.ack_count(), acks_before);
    operation.abort();
    assert!(operation.await.expect_err("cancelled join").is_cancelled());
    fixture.runtime.release_v2_resume();
    assert_eq!(fixture.runtime.ack_count(), acks_before);

    let reopened = fixture.reopen().await;
    fixture.runtime.force_retention_v2_gap_once();
    let snapshot = reopened
        .open_project_conversation(fixture.project_id)
        .await
        .expect("reopened retry");
    assert_eq!(snapshot.stream_version, 3);
    assert_eq!(fixture.runtime.ack_count(), acks_before + 1);
}

#[tokio::test]
async fn taskrun_uses_the_same_v2_coordinator_without_a_renderer_surface() {
    let fixture = support::Fixture::opened().await;
    let acks_before = fixture.runtime.ack_count();
    fixture.runtime.force_retention_v2_gap_once();
    let task_run = runne_app_core::CanonicalId::parse("018f2e3a-7000-7000-8000-000000000150")
        .expect("TaskRun ID");

    runne_app_core::test_support::promote_task_run_v2_for_test(&fixture.core, task_run)
        .await
        .expect("TaskRun V2 promotion");

    assert_eq!(fixture.runtime.ack_count(), acks_before + 1);
    let taskrun_shadows: i64 = rusqlite::Connection::open(&fixture.database_path)
        .expect("database")
        .query_row(
            "SELECT COUNT(*) FROM replay_shadow_generations WHERE scope LIKE 'task_run:%'",
            [],
            |row| row.get(0),
        )
        .expect("TaskRun shadow");
    assert_eq!(taskrun_shadows, 1);
}

#[tokio::test]
async fn malformed_v2_admission_responses_close_the_server_session() {
    for mode in [1, 2, 3] {
        let fixture = support::Fixture::opened().await;
        fixture.runtime.reset_close_count().await;
        fixture.runtime.malform_next_v2_resume_response(mode);
        fixture.runtime.force_retention_v2_gap_once();

        fixture
            .core
            .open_project_conversation(fixture.project_id)
            .await
            .expect_err("malformed V2 response");

        fixture.runtime.wait_for_close(1).await;
        assert_eq!(fixture.runtime.close_count(), 1);
    }
}

#[tokio::test]
async fn malformed_live_delivery_id_closes_the_promoted_server_session() {
    let fixture = support::Fixture::opened().await;
    fixture.runtime.reset_close_count().await;
    fixture.runtime.malform_next_live_delivery_id();
    fixture.runtime.force_retention_v2_gap_once();

    fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("malformed live delivery id");

    fixture.runtime.wait_for_close(1).await;
    assert_eq!(fixture.runtime.close_count(), 1);
}
