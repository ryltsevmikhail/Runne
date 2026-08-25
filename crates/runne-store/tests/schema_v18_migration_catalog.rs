use runne_domain::event::{Actor, EventEnvelope, Sensitivity};
use runne_domain::id::{
    AggregateId, CommandId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId,
};
use runne_domain::task_run::TaskRunEvent;
use runne_domain::timestamp::Timestamp;
use runne_store::codec::{StoreCodec, TaskRunEventCodec};
use runne_store::integrity::compute_integrity_digest_with_global_position;
use runne_store::schema::{
    apply_migrations, apply_migrations_through_v18_for_test, apply_migrations_through_v19_for_test,
};
use rusqlite::{Connection, params};

#[test]
fn complete_v19_history_rebuilds_to_v23() {
    let connection = v19_taskrun();
    apply_migrations(&connection).unwrap();
    assert_eq!(version(&connection), 23);
    let projection: Vec<u8> = connection
        .query_row(
            "SELECT promotion_projection_bytes FROM aggregate_state_snapshots",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!projection.is_empty());
}

#[test]
fn pruned_v19_history_fails_closed_without_catalog_or_snapshot_changes() {
    let connection = v19_taskrun();
    let before_catalog = catalog(&connection);
    let before_user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let before_snapshot = v19_snapshot_row(&connection);
    connection
        .execute("DELETE FROM events WHERE aggregate_type = 1", [])
        .unwrap();
    assert!(apply_migrations(&connection).is_err());
    assert_eq!(version(&connection), 19);
    assert_eq!(catalog(&connection), before_catalog);
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        before_user_version
    );
    assert_eq!(v19_snapshot_row(&connection), before_snapshot);
}

type V19SnapshotRow = (
    i64,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
);

fn v19_snapshot_row(connection: &Connection) -> V19SnapshotRow {
    connection
        .query_row(
            "SELECT aggregate_type, aggregate_id, codec_version, aggregate_version, event_sequence,
                head_event_id, head_integrity_digest, projection_bytes, projection_digest,
                head_global_position, snapshot_integrity_digest
         FROM aggregate_state_snapshots",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .unwrap()
}

fn v19_taskrun() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_through_v18_for_test(&connection).unwrap();
    let id: TaskRunId = "018f2e3a-7000-7000-8000-000000000201".parse().unwrap();
    let event_id: EventId = "018f2e3a-7000-7000-8000-000000000202".parse().unwrap();
    let command: CommandId = "018f2e3a-7000-7000-8000-000000000203".parse().unwrap();
    let event = EventEnvelope::from_parts(
        event_id,
        AggregateId::TaskRun(id),
        AggregateId::TaskRun(id),
        None,
        command,
        IdempotencyKey::new("v19-history").unwrap(),
        1,
        Actor::new("v19").unwrap(),
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let payload = TaskRunEventCodec.encode(event.payload()).unwrap();
    let digest = compute_integrity_digest_with_global_position(&event, 1, &payload).unwrap();
    connection.execute("INSERT INTO aggregate_streams (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) VALUES (1, ?1, 1, ?2, 1, 1)", params![id.as_bytes(), event_id.as_bytes()]).unwrap();
    connection.execute("INSERT INTO events (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile) VALUES (?1, 1, ?2, 1, 1, 1, 0, 1, NULL, ?3, ?4, ?5, ?6, ?7, ?2, 1, 1)", params![event_id.as_bytes(), id.as_bytes(), command.as_bytes(), event.idempotency_key().as_str().as_bytes(), event.actor().as_str().as_bytes(), payload, digest.as_bytes()]).unwrap();
    apply_migrations_through_v19_for_test(&connection).unwrap();
    connection
}

fn version(connection: &Connection) -> i64 {
    connection
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn catalog(connection: &Connection) -> Vec<(String, String, Option<String>)> {
    connection
        .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
