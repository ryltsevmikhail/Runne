use std::path::Path;

use gocode_local_store::{
    LocalStore, ReplayCheckpoint, ReplayScopeKey, ReplayStoreError, ReplayTransition,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

const BINDING_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn scope() -> ReplayScopeKey {
    ReplayScopeKey {
        runtime_authority: "runtime-1".into(),
        principal: "principal-1".into(),
        lineage: "lineage-1".into(),
        scope: "conversation-1".into(),
        binding_digest: BINDING_DIGEST.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn transition<'a>(
    scope: &'a ReplayScopeKey,
    expected_checkpoint: Option<&'a ReplayCheckpoint>,
    event_id: &'a str,
    cursor: &'a str,
    event_sequence: u64,
    event_bytes: &'a [u8],
    projection_revision: u64,
    projection_bytes: &'a [u8],
) -> ReplayTransition<'a> {
    ReplayTransition {
        scope,
        expected_checkpoint,
        event_id,
        cursor,
        generation: 7,
        event_sequence,
        event_bytes,
        event_digest: digest(event_bytes),
        projection_revision,
        projection_bytes,
        projection_digest: digest(projection_bytes),
    }
}

fn assert_failure_rolls_back_all_three_records(path: &Path, trigger_sql: &str) {
    let scope = scope();
    let old_event = br#"{"eventId":"event-1","sequence":1}"#;
    let old_projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let mut store = LocalStore::open(path).expect("open store");
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            1,
            old_event,
            1,
            old_projection,
        ))
        .expect("apply baseline");
    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read checkpoint")
        .expect("checkpoint");
    drop(store);

    let connection = Connection::open(path).expect("open for failure injection");
    connection
        .execute_batch(trigger_sql)
        .expect("install failure trigger");
    drop(connection);

    let new_event = br#"{"eventId":"event-2","sequence":2}"#;
    let new_projection = br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#;
    let mut store = LocalStore::open(path).expect("reopen store");
    let error = store
        .apply_replay_transition(&transition(
            &scope,
            Some(&checkpoint),
            "event-2",
            "opaque.cursor.2",
            2,
            new_event,
            2,
            new_projection,
        ))
        .expect_err("injected failure");
    assert!(matches!(error, ReplayStoreError::Storage(_)));
    drop(store);

    let store = LocalStore::open(path).expect("reopen after failure");
    let actual_checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read checkpoint after failure")
        .expect("checkpoint after failure");
    let actual_projection = store
        .conversation_projection(&scope)
        .expect("read projection after failure")
        .expect("projection after failure");
    assert_eq!(actual_checkpoint, checkpoint);
    assert_eq!(actual_projection.payload, old_projection);
    assert_eq!(actual_projection.revision, 1);
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        2
    );
    drop(store);

    let connection = Connection::open(path).expect("inspect journal after failure");
    let event_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM event_journal", [], |row| row.get(0))
        .expect("count journal");
    assert_eq!(event_count, 1);
}

#[test]
fn crash_before_journal_insert_leaves_old_atomic_state() {
    let directory = tempfile::tempdir().expect("temp directory");
    assert_failure_rolls_back_all_three_records(
        &directory.path().join("profile.sqlite3"),
        "
        CREATE TRIGGER fail_before_journal_insert
        BEFORE INSERT ON event_journal
        BEGIN
            SELECT RAISE(ABORT, 'injected before journal insert');
        END;
        ",
    );
}

#[test]
fn crash_after_journal_insert_leaves_old_atomic_state() {
    let directory = tempfile::tempdir().expect("temp directory");
    assert_failure_rolls_back_all_three_records(
        &directory.path().join("profile.sqlite3"),
        "
        CREATE TRIGGER fail_after_journal_insert
        AFTER INSERT ON event_journal
        BEGIN
            SELECT RAISE(ABORT, 'injected after journal insert');
        END;
        ",
    );
}

#[test]
fn crash_after_projection_update_leaves_old_atomic_state() {
    let directory = tempfile::tempdir().expect("temp directory");
    assert_failure_rolls_back_all_three_records(
        &directory.path().join("profile.sqlite3"),
        "
        CREATE TRIGGER fail_after_projection_update
        AFTER UPDATE ON projections
        BEGIN
            SELECT RAISE(ABORT, 'injected after projection update');
        END;
        ",
    );
}

#[test]
fn crash_after_cursor_update_before_commit_leaves_old_atomic_state() {
    let directory = tempfile::tempdir().expect("temp directory");
    assert_failure_rolls_back_all_three_records(
        &directory.path().join("profile.sqlite3"),
        "
        CREATE TRIGGER fail_after_cursor_update
        AFTER UPDATE ON replay_cursors
        BEGIN
            SELECT RAISE(ABORT, 'injected after cursor update');
        END;
        ",
    );
}
