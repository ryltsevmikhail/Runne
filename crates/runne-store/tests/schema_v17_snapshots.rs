use runne_domain::{
    event::{Actor, EventEnvelope, Sensitivity},
    id::{AggregateId, CommandId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId},
    task_run::TaskRunEvent,
    timestamp::Timestamp,
};
use runne_store::schema::{
    CURRENT_SCHEMA_VERSION, apply_migrations, apply_migrations_through_v15_for_test,
    apply_migrations_through_v17_for_test, apply_migrations_through_v18_for_test,
    apply_migrations_through_v19_for_test,
};
use runne_store::{
    codec::{StoreCodec, TaskRunEventCodec},
    integrity::compute_integrity_digest_with_global_position,
};
use rusqlite::{Connection, params};

#[test]
fn current_schema_installs_authoritative_aggregate_snapshot_table() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();

    assert_eq!(CURRENT_SCHEMA_VERSION, 20);
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'aggregate_state_snapshots')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(exists);
    let integrity_column: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('aggregate_state_snapshots')
             WHERE name = 'snapshot_integrity_digest')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(integrity_column);
    apply_migrations(&connection).unwrap();
}

#[test]
fn snapshot_insert_without_an_exact_stream_head_is_rejected() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();

    let rejected = connection.execute(
        "INSERT INTO aggregate_state_snapshots
         (aggregate_type, aggregate_id, codec_version, aggregate_version, event_sequence,
          head_event_id, head_integrity_digest, projection_bytes, projection_digest,
          head_global_position, snapshot_integrity_digest)
         VALUES (1, ?1, 1, 1, 1, ?1, zeroblob(32), x'01', zeroblob(32), 1, zeroblob(32))",
        params![[0xA5_u8; 16]],
    );
    assert!(rejected.is_err());
}

#[test]
fn released_v15_without_aggregate_histories_upgrades_through_main_v17() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_through_v15_for_test(&connection).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        15,
    );
    apply_migrations_through_v17_for_test(&connection).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        17,
    );

    apply_migrations_through_v17_for_test(&connection).unwrap();
}

#[test]
fn released_main_v17_is_preserved_before_v18_project_workspace_successor() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_through_v17_for_test(&connection).unwrap();

    apply_migrations_through_v18_for_test(&connection).unwrap();

    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        18,
    );
    for table in ["bootstrap_reservations", "projects", "workspaces"] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "{table} must survive the V18 successor");
    }
}

#[test]
fn released_v15_with_a_complete_typed_taskrun_history_backfills_v19() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_through_v15_for_test(&connection).unwrap();
    let taskrun_id: TaskRunId = "018f2e3a-7000-7000-8000-0000000000d1".parse().unwrap();
    let event_id: EventId = "018f2e3a-7000-7000-8000-0000000000d2".parse().unwrap();
    let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000000d3".parse().unwrap();
    let event = EventEnvelope::from_parts(
        event_id,
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        None,
        command_id,
        IdempotencyKey::new("v15-snapshot-history").unwrap(),
        1,
        Actor::new("v15-snapshot").unwrap(),
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let payload = TaskRunEventCodec.encode(event.payload()).unwrap();
    let digest = compute_integrity_digest_with_global_position(&event, 1, &payload).unwrap();
    connection.execute("INSERT INTO aggregate_streams (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) VALUES (1, ?1, 1, ?2, 1, 1)", params![taskrun_id.as_bytes(), event_id.as_bytes()]).unwrap();
    connection.execute("INSERT INTO events (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile) VALUES (?1, 1, ?2, 1, 1, 1, 0, 1, NULL, ?3, ?4, ?5, ?6, ?7, ?2, 1, 1)", params![event_id.as_bytes(), taskrun_id.as_bytes(), command_id.as_bytes(), event.idempotency_key().as_str().as_bytes(), event.actor().as_str().as_bytes(), payload, digest.as_bytes()]).unwrap();
    apply_migrations_through_v18_for_test(&connection).unwrap();
    apply_migrations_through_v19_for_test(&connection).unwrap();
    assert_eq!(connection.query_row("SELECT aggregate_version FROM aggregate_state_snapshots WHERE aggregate_type = 1 AND aggregate_id = ?1", [taskrun_id.as_bytes()], |row| row.get::<_, i64>(0)).unwrap(), 1);
}
