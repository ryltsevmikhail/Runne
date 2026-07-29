//! Интеграционные тесты server-issued catch-up и acknowledge ReplayStore.

use gocode_application::ports::{
    ReplayError, ReplayEvent, ReplaySession, ReplayState, ReplayStorePort,
};
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{
    AggregateId, CommandId, EventId, EventLogLineageId, IdempotencyKey, IntegrityDigest, TaskRunId,
};
use gocode_domain::replay::{CURSOR_SCHEMA_VERSION, ReplayCursor, ReplayScope};
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;
use gocode_store::codec::{StoreCodec, TaskRunEventCodec};
use gocode_store::integrity::compute_integrity_digest_with_global_position;
use gocode_store::replay_store::ReplayStore;
use gocode_store::schema::apply_migrations;
use rusqlite::Connection;
use tempfile::TempDir;

const AUTHORITY: [u8; 16] = [0xAA; 16];
const AGGREGATE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0xbb,
];
const SECRET: [u8; 32] = [0xCC; 32];

struct TaskRunRow {
    event_id: [u8; 16],
    idempotency_key: Vec<u8>,
    actor: &'static [u8],
    payload: Vec<u8>,
    integrity_digest: [u8; 32],
}

fn event_id(global_position: i64) -> [u8; 16] {
    let mut bytes = [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0,
    ];
    bytes[14..].copy_from_slice(
        &u16::try_from(global_position)
            .expect("test position fits u16")
            .to_be_bytes(),
    );
    bytes
}

fn taskrun_row(aggregate: [u8; 16], sequence: i64, global_position: i64) -> TaskRunRow {
    let event_id_bytes = event_id(global_position);
    let taskrun_id = TaskRunId::from_bytes(aggregate);
    let event_id = EventId::from_bytes(event_id_bytes);
    let command_id = CommandId::from_bytes(event_id_bytes);
    let idempotency_key = IdempotencyKey::new(format!("replay-event-{global_position}")).unwrap();
    let actor = Actor::new("test-actor").unwrap();
    let payload = TaskRunEvent::TaskRunCreated;
    let payload_bytes = TaskRunEventCodec.encode(&payload).unwrap();
    let envelope = EventEnvelope::from_parts(
        event_id,
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        None,
        command_id,
        idempotency_key.clone(),
        1,
        actor,
        Sensitivity::Public,
        payload,
        u64::try_from(sequence).unwrap(),
        Timestamp::from_unix_micros(0),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let integrity_digest =
        compute_integrity_digest_with_global_position(&envelope, global_position, &payload_bytes)
            .unwrap()
            .into_bytes();
    TaskRunRow {
        event_id: event_id_bytes,
        idempotency_key: idempotency_key.as_str().as_bytes().to_vec(),
        actor: b"test-actor",
        payload: payload_bytes,
        integrity_digest,
    }
}

fn store() -> ReplayStore {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    ReplayStore::new(connection)
}

fn store_with_events(count: i64) -> ReplayStore {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams \
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) \
             VALUES (1, ?1, ?2, ?3, 0, 0)",
            rusqlite::params![AGGREGATE.as_slice(), count, event_id(count).as_slice()],
        )
        .unwrap();
    for position in 1..=count {
        let row = taskrun_row(AGGREGATE, position, position);
        connection
            .execute(
                "INSERT INTO events \
                 (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
                  sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
                  payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
                 VALUES (?1, 1, ?2, ?3, ?3, 0, 0, 1, NULL, ?1, ?4, ?5, ?6, ?7, ?2, 1, 1)",
                rusqlite::params![
                    row.event_id.as_slice(),
                    AGGREGATE.as_slice(),
                    position,
                    row.idempotency_key,
                    row.actor,
                    row.payload,
                    row.integrity_digest.as_slice(),
                ],
            )
            .unwrap();
    }
    ReplayStore::new(connection)
}

fn store_with_scoped_and_unrelated_event() -> ReplayStore {
    const OTHER_AGGREGATE: [u8; 16] = [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0xdd,
    ];

    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    for (aggregate_id, position) in [(AGGREGATE, 1_i64), (OTHER_AGGREGATE, 2_i64)] {
        let row = taskrun_row(aggregate_id, 1, position);
        connection
            .execute(
                "INSERT INTO aggregate_streams \
                 (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) \
                 VALUES (1, ?1, 1, ?2, 0, 0)",
                rusqlite::params![aggregate_id.as_slice(), row.event_id.as_slice()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO events \
                 (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
                  sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
                  payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
                 VALUES (?1, 1, ?2, 1, ?3, 0, 0, 1, NULL, ?1, ?4, ?5, ?6, ?7, ?2, 1, 1)",
                rusqlite::params![
                    row.event_id.as_slice(),
                    aggregate_id.as_slice(),
                    position,
                    row.idempotency_key,
                    row.actor,
                    row.payload,
                    row.integrity_digest.as_slice(),
                ],
            )
            .unwrap();
    }
    ReplayStore::new(connection)
}

fn file_store_with_events(count: i64) -> (ReplayStore, Connection, TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replay.sqlite");
    let connection = Connection::open(&path).unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams \
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) \
             VALUES (1, ?1, ?2, ?3, 0, 0)",
            rusqlite::params![AGGREGATE.as_slice(), count, event_id(count).as_slice()],
        )
        .unwrap();
    for position in 1..=count {
        let row = taskrun_row(AGGREGATE, position, position);
        connection
            .execute(
                "INSERT INTO events \
                 (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
                  sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
                  payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
                 VALUES (?1, 1, ?2, ?3, ?3, 0, 0, 1, NULL, ?1, ?4, ?5, ?6, ?7, ?2, 1, 1)",
                rusqlite::params![
                    row.event_id.as_slice(),
                    AGGREGATE.as_slice(),
                    position,
                    row.idempotency_key,
                    row.actor,
                    row.payload,
                    row.integrity_digest.as_slice(),
                ],
            )
            .unwrap();
    }
    let writer = Connection::open(&path).unwrap();
    (ReplayStore::new(connection), writer, directory)
}

async fn open(
    store: &ReplayStore,
    from_cursor: Option<&ReplayCursor>,
) -> (ReplaySession, Vec<ReplayEvent>) {
    store
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            0,
            1,
            &AGGREGATE,
            from_cursor,
            &SECRET,
        )
        .await
        .unwrap()
}

fn cursor(position: i64) -> ReplayCursor {
    ReplayCursor {
        event_id: EventId::from_bytes(event_id(position)),
        aggregate_id: AggregateId::TaskRun(TaskRunId::from_bytes(AGGREGATE)),
        sequence: position as u64,
        global_position: position,
        lineage_id: EventLogLineageId::from_bytes([2; 16]),
        scope: ReplayScope::Aggregate {
            aggregate_type: 1,
            aggregate_id: AGGREGATE,
        },
        schema_version: CURSOR_SCHEMA_VERSION,
        sensitivity: Sensitivity::Public,
        event_type: "TaskRunCreated".into(),
        integrity: IntegrityDigest::from_bytes([0; 32]),
    }
}

#[tokio::test]
async fn empty_catch_up_has_server_issued_proof() {
    let store = store();
    let (session, events) = store
        .open_session("principal", 1, &AUTHORITY, 0, 1, &AGGREGATE, None, &SECRET)
        .await
        .unwrap();
    assert!(events.is_empty());
    let (completed, last_ack_event) = store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap();
    assert_eq!(completed.state, ReplayState::CatchUpComplete);
    assert!(last_ack_event.is_none());
    assert_eq!(
        completed.catch_up_completion.as_ref().map(Vec::len),
        Some(32)
    );
}

#[tokio::test]
async fn nonempty_catch_up_requires_acknowledgement() {
    let store = store();
    let (session, _) = store
        .open_session("principal", 1, &AUTHORITY, 0, 1, &AGGREGATE, None, &SECRET)
        .await
        .unwrap();
    let error = store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ReplayError::NotAcknowledged));
}

#[tokio::test]
async fn test_open_session_returns_empty_for_empty_db() {
    let store = store();

    let (_, events) = open(&store, None).await;

    assert!(events.is_empty());
}

#[tokio::test]
async fn test_open_session_with_events_returns_all_events() {
    let store = store_with_events(3);

    let (_, events) = open(&store, None).await;

    assert_eq!(
        events
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
}

#[tokio::test]
async fn test_from_cursor_inclusive() {
    let store = store_with_events(3);

    let (_, events) = open(&store, Some(&cursor(2))).await;

    assert_eq!(
        events
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>(),
        [2, 3]
    );
}

#[tokio::test]
async fn open_session_rejects_cursor_for_unknown_event_position() {
    let store = store_with_events(1);

    let error = store
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            0,
            1,
            &AGGREGATE,
            Some(&cursor(2)),
            &SECRET,
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::CursorInvalid { reason: _ }));
}

#[tokio::test]
async fn test_read_page_pagination() {
    let store = store_with_events(102);
    let (session, initial_events) = open(&store, None).await;
    assert_eq!(initial_events.len(), 100);

    let first_page = store
        .read_page(&session.session_id, "principal", 1, &AUTHORITY, 0, 1)
        .await
        .unwrap();
    let second_page = store
        .read_page(&session.session_id, "principal", 1, &AUTHORITY, 0, 1)
        .await
        .unwrap();

    assert_eq!(first_page.1[0].global_position, 101);
    assert_eq!(second_page.1[0].global_position, 102);
    assert!(first_page.0.next_page_position.is_some());
    assert!(second_page.0.next_page_position.is_none());
}

#[tokio::test]
async fn exact_full_initial_page_can_complete_after_acknowledgement() {
    let store = store_with_events(100);
    let (session, initial_events) = open(&store, None).await;
    assert_eq!(initial_events.len(), 100);

    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(100),
        )
        .await
        .unwrap();

    let (completed, last_ack_event) = store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap();

    assert_eq!(completed.state, ReplayState::CatchUpComplete);
    assert_eq!(last_ack_event.unwrap().global_position, 100);
}

#[tokio::test]
async fn catch_up_completion_uses_last_event_in_scope() {
    let store = store_with_scoped_and_unrelated_event();
    let (session, initial_events) = open(&store, None).await;
    assert_eq!(
        initial_events
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>(),
        [1]
    );

    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
        )
        .await
        .unwrap();

    let (completed, last_ack_event) = store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap();

    assert_eq!(completed.state, ReplayState::CatchUpComplete);
    assert_eq!(last_ack_event.unwrap().global_position, 1);
}

#[tokio::test]
async fn test_acknowledge_monotonic() {
    let store = store_with_events(2);
    let (session, _) = open(&store, None).await;

    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
        )
        .await
        .unwrap();
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(2),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_acknowledge_duplicate_idempotent() {
    let store = store_with_events(1);
    let (session, _) = open(&store, None).await;

    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
        )
        .await
        .unwrap();
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn acknowledge_rejects_cursor_not_delivered_by_session() {
    let store = store_with_events(1);
    let (session, _) = open(&store, None).await;
    let mut forged_cursor = cursor(1);
    forged_cursor.event_id = EventId::from_bytes([0xEE; 16]);

    let error = store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &forged_cursor,
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::CursorInvalid { reason: _ }));
}

#[tokio::test]
async fn test_complete_catch_up_requires_ack() {
    let store = store_with_events(1);
    let (session, _) = open(&store, None).await;

    let error = store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::NotAcknowledged));
}

#[tokio::test]
async fn test_complete_catch_up_success() {
    let store = store_with_events(2);
    let (session, _) = open(&store, None).await;
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(2),
        )
        .await
        .unwrap();

    let (completed, last_ack_event) = store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap();

    assert_eq!(completed.state, ReplayState::CatchUpComplete);
    assert_eq!(last_ack_event.unwrap().global_position, 2);
}

#[tokio::test]
async fn duplicate_complete_catch_up_returns_same_server_proof() {
    let store = store_with_events(1);
    let (session, _) = open(&store, None).await;
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
        )
        .await
        .unwrap();

    let first = store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap();
    let second = store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap();

    assert_eq!(first.0.catch_up_completion, second.0.catch_up_completion);
    assert_eq!(first.1.unwrap().global_position, 1);
    assert_eq!(second.1.unwrap().global_position, 1);
    assert_eq!(second.0.state, ReplayState::CatchUpComplete);
}

#[tokio::test]
async fn test_continue_live_cas() {
    let store = store_with_events(1);
    let (session, _) = open(&store, None).await;
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
        )
        .await
        .unwrap();
    store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap();

    let first = store
        .continue_live(&session.session_id, "principal", 1, &AUTHORITY, 0)
        .await;
    let second = store
        .continue_live(&session.session_id, "principal", 1, &AUTHORITY, 0)
        .await;

    assert!(matches!(
        first,
        Ok(ReplaySession {
            state: ReplayState::Live,
            ..
        })
    ));
    assert!(matches!(second, Err(ReplayError::InvalidState(_))));
}

#[tokio::test]
async fn poll_live_advances_past_delivered_events() {
    let (store, writer, _directory) = file_store_with_events(1);
    let (session, _) = open(&store, None).await;
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
        )
        .await
        .unwrap();
    store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap();
    store
        .continue_live(&session.session_id, "principal", 1, &AUTHORITY, 0)
        .await
        .unwrap();

    let row = taskrun_row(AGGREGATE, 2, 2);
    writer
        .execute(
            "INSERT INTO events \
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
             VALUES (?1, 1, ?2, 2, 2, 0, 0, 1, NULL, ?1, ?3, ?4, ?5, ?6, ?2, 1, 1)",
            rusqlite::params![
                row.event_id.as_slice(),
                AGGREGATE.as_slice(),
                row.idempotency_key,
                row.actor,
                row.payload,
                row.integrity_digest.as_slice(),
            ],
        )
        .unwrap();
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = 2, last_event_id = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            rusqlite::params![row.event_id.as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();

    let first = store
        .poll_live(&session.session_id, "principal", 1, &AUTHORITY, 0)
        .await
        .unwrap();
    let second = store
        .poll_live(&session.session_id, "principal", 1, &AUTHORITY, 0)
        .await
        .unwrap();

    assert_eq!(
        first
            .1
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>(),
        [2]
    );
    assert!(second.1.is_empty());
}

#[tokio::test]
async fn replay_rejects_interior_sequence_gap() {
    let (store, writer, _directory) = file_store_with_events(3);
    writer
        .execute("DELETE FROM events WHERE global_position = 2", [])
        .unwrap();

    let result = store
        .open_session("principal", 1, &AUTHORITY, 0, 1, &AGGREGATE, None, &SECRET)
        .await;

    assert!(matches!(result, Err(ReplayError::Integrity(_))));
}

#[tokio::test]
async fn poll_live_rejects_sequence_jump() {
    let (store, writer, _directory) = file_store_with_events(1);
    let (session, _) = open(&store, None).await;
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
        )
        .await
        .unwrap();
    store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap();
    store
        .continue_live(&session.session_id, "principal", 1, &AUTHORITY, 0)
        .await
        .unwrap();

    let row = taskrun_row(AGGREGATE, 3, 2);
    writer
        .execute(
            "INSERT INTO events \
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
             VALUES (?1, 1, ?2, 3, 2, 0, 0, 1, NULL, ?1, ?3, ?4, ?5, ?6, ?2, 1, 1)",
            rusqlite::params![
                row.event_id.as_slice(),
                AGGREGATE.as_slice(),
                row.idempotency_key,
                row.actor,
                row.payload,
                row.integrity_digest.as_slice(),
            ],
        )
        .unwrap();
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = 3, last_event_id = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            rusqlite::params![row.event_id.as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();

    let result = store
        .poll_live(&session.session_id, "principal", 1, &AUTHORITY, 0)
        .await;

    assert!(matches!(result, Err(ReplayError::Integrity(_))));
}

#[tokio::test]
async fn replay_rejects_payload_changed_without_integrity_digest_update() {
    let (store, writer, _directory) = file_store_with_events(1);
    writer
        .execute(
            "UPDATE events SET payload = x'000102' WHERE global_position = 1",
            [],
        )
        .unwrap();

    let result = store
        .open_session("principal", 1, &AUTHORITY, 0, 1, &AGGREGATE, None, &SECRET)
        .await;

    assert!(matches!(result, Err(ReplayError::Integrity(_))));
}

#[tokio::test]
async fn test_close_session() {
    let store = store();
    let (session, _) = open(&store, None).await;
    store
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 0, &SECRET)
        .await
        .unwrap();

    store
        .close_session(&session.session_id, "principal", 1, &AUTHORITY, 0)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_reconnect_from_ack() {
    let store = store_with_events(3);
    let (session, _) = open(&store, None).await;
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(2),
        )
        .await
        .unwrap();

    let (_, events) = open(&store, Some(&cursor(2))).await;

    assert_eq!(
        events
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>(),
        [2, 3]
    );
}
