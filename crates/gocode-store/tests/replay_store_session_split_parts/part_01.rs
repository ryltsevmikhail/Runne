use std::sync::Arc;

use gocode_application::ports::{
    ReplayError, ReplayEvent, ReplaySession, ReplayState, ReplayStorePort,
};
use gocode_application::replay_service::ReplayDeliveryPrecommitGuard;
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
use gocode_store::schema::{
    ConnectionMode, ManagedConnection, apply_migrations, open_managed_connection,
};
use rusqlite::Connection;
use tempfile::TempDir;

const AUTHORITY: [u8; 16] = [0xAA; 16];
const AGGREGATE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0xbb,
];
const SECRET: [u8; 32] = [0xCC; 32];
const LINEAGE: [u8; 16] = [0x02; 16];

struct AvailableDeliveryGuard;

impl ReplayDeliveryPrecommitGuard for AvailableDeliveryGuard {
    fn inspect(
        &self,
        _session: &ReplaySession,
        _events: &[ReplayEvent],
    ) -> Result<(), ReplayError> {
        Ok(())
    }
}

fn delivery_guard() -> Arc<dyn ReplayDeliveryPrecommitGuard> {
    Arc::new(AvailableDeliveryGuard)
}

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
    ReplayStore::new(managed_memory())
}

fn store_with_events(count: i64) -> ReplayStore {
    let connection = managed_memory();
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

    let connection = managed_memory();
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
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
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

fn managed_memory() -> ManagedConnection {
    let connection =
        open_managed_connection(std::path::Path::new(":memory:"), ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    connection
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
            &EventLogLineageId::from_bytes(LINEAGE),
            &SECRET,
            delivery_guard(),
        )
        .await
        .unwrap()
        .into_opened()
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
