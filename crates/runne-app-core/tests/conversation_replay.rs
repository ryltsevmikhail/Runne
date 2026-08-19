mod support;

use runne_app_core::{ConversationRecoveryDisposition, ConversationSnapshot};
use rusqlite::Connection;
use support::Fixture;

#[test]
fn snapshot_carries_projection_revision_and_closed_recovery() {
    let snapshot = ConversationSnapshot {
        conversation_id: "018f2e3a-7000-7000-8000-000000000110".to_owned(),
        projection_revision: 3,
        stream_version: 3,
        messages: Vec::new(),
        recovery: ConversationRecoveryDisposition::Live,
    };

    assert_eq!(snapshot.projection_revision, 3);
    assert_eq!(snapshot.recovery, ConversationRecoveryDisposition::Live);
    let value = serde_json::to_value(snapshot).expect("serialize snapshot");
    assert_eq!(
        value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "conversationId",
            "messages",
            "projectionRevision",
            "recovery",
            "streamVersion",
        ]
    );
}

#[tokio::test]
async fn local_replay_failure_stops_before_ack_and_update() {
    let fixture = Fixture::opened().await;
    let updates = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscription = fixture.subscribe(std::sync::Arc::clone(&updates));
    fixture.runtime.wait_for_live(1).await;
    let acknowledged_before = fixture.runtime.ack_count();
    Connection::open(&fixture.database_path)
        .expect("open database")
        .execute_batch(
            "
            CREATE TRIGGER fail_event_journal_insert
            BEFORE INSERT ON event_journal
            BEGIN
                SELECT RAISE(FAIL, 'forced local failure');
            END;
            ",
        )
        .expect("install failure");

    fixture.runtime.append_generation_failed();
    let error = subscription
        .await
        .expect("subscription task")
        .expect_err("local failure");

    assert_eq!(error.to_string(), "local_projection_unavailable");
    assert_eq!(fixture.runtime.ack_count(), acknowledged_before);
    assert!(updates.lock().expect("updates").is_empty());
}

#[tokio::test]
async fn runtime_identity_conflict_preserves_projection_and_sends_no_command() {
    let fixture = Fixture::opened().await;
    let connection = Connection::open(&fixture.database_path).expect("open database");
    let before: (Vec<u8>, String) = connection
        .query_row(
            "
            SELECT projections.payload, replay_cursors.applied_cursor
            FROM projections
            JOIN replay_cursors USING (runtime_authority, principal, lineage, scope)
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("projection and cursor");
    let key = format!("runtime.conversation.project.{}", fixture.project_id);
    let serialized: String = connection
        .query_row("SELECT value FROM settings WHERE key = ?1", [&key], |row| {
            row.get(0)
        })
        .expect("reference");
    let mut reference: serde_json::Value =
        serde_json::from_str(&serialized).expect("reference JSON");
    reference["runtimeAuthority"] = serde_json::json!("018f2e3a700070008000000000000099");
    connection
        .execute(
            "UPDATE settings SET value = ?1 WHERE key = ?2",
            [
                serde_json::to_string(&reference).expect("reference JSON"),
                key,
            ],
        )
        .expect("replace reference");
    let create_before = fixture.runtime.create_count();

    let error = fixture
        .core
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("identity conflict");

    assert_eq!(error.to_string(), "runtime_identity_conflict");
    assert_eq!(fixture.runtime.create_count(), create_before);
    let after: (Vec<u8>, String) = connection
        .query_row(
            "
            SELECT projections.payload, replay_cursors.applied_cursor
            FROM projections
            JOIN replay_cursors USING (runtime_authority, principal, lineage, scope)
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("projection and cursor");
    assert_eq!(after, before);
}
