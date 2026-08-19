use runne_domain::{
    event::{Actor, EventEnvelope, Sensitivity},
    id::{AggregateId, CommandId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId},
    task_run::TaskRunEvent,
    timestamp::Timestamp,
};
use rusqlite::{Connection, TransactionBehavior, params};

use super::{
    CORRELATION_TYPE_TASK_RUN, load_unauthenticated_replay_projection, refresh_aggregate_snapshot,
};
use crate::{
    codec::{StoreCodec, TaskRunEventCodec},
    integrity::compute_integrity_digest_with_global_position,
    schema::apply_migrations,
};

#[test]
fn private_loader_rechecks_stream_head_in_the_callers_transaction() {
    let mut connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    let taskrun_id: TaskRunId = "018f2e3a-7000-7000-8000-0000000000c1".parse().unwrap();
    let event_id: EventId = "018f2e3a-7000-7000-8000-0000000000c2".parse().unwrap();
    let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000000c3".parse().unwrap();
    let event = EventEnvelope::from_parts(
        event_id,
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        None,
        command_id,
        IdempotencyKey::new("snapshot-loader").unwrap(),
        1,
        Actor::new("snapshot-loader").unwrap(),
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let payload = TaskRunEventCodec.encode(event.payload()).unwrap();
    let digest = compute_integrity_digest_with_global_position(&event, 1, &payload).unwrap();
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute(
        "INSERT INTO aggregate_streams (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
         VALUES (1, ?1, 1, ?2, 1, 1)",
        params![taskrun_id.as_bytes(), event_id.as_bytes()],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO events (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version,
          causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile)
         VALUES (?1, 1, ?2, 1, 1, 1, 0, 1, NULL, ?3, ?4, ?5, ?6, ?7, ?2, 1, 1)",
        params![event_id.as_bytes(), taskrun_id.as_bytes(), command_id.as_bytes(), event.idempotency_key().as_str().as_bytes(), event.actor().as_str().as_bytes(), payload, digest.as_bytes()],
    )
    .unwrap();
    refresh_aggregate_snapshot(&tx, CORRELATION_TYPE_TASK_RUN, taskrun_id.as_bytes()).unwrap();
    assert!(
        load_unauthenticated_replay_projection(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            taskrun_id.as_bytes()
        )
        .is_ok()
    );
    tx.execute(
        "UPDATE events SET payload = x'00' WHERE event_id = ?1",
        [event_id.as_bytes()],
    )
    .unwrap();
    assert!(
        load_unauthenticated_replay_projection(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            taskrun_id.as_bytes()
        )
        .is_err()
    );
    tx.execute(
        "UPDATE events SET payload = ?1 WHERE event_id = ?2",
        params![payload, event_id.as_bytes()],
    )
    .unwrap();
    tx.execute(
        "UPDATE events SET event_id = zeroblob(16) WHERE event_id = ?1",
        [event_id.as_bytes()],
    )
    .unwrap();
    assert!(
        load_unauthenticated_replay_projection(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            taskrun_id.as_bytes()
        )
        .is_err()
    );
    tx.execute(
        "UPDATE events SET event_id = ?1 WHERE event_id = zeroblob(16)",
        [event_id.as_bytes()],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO events (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
          sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, payload,
          integrity_digest, correlation_id, correlation_type, integrity_profile)
         VALUES (zeroblob(16), 1, ?1, 2, 2, 2, 0, 1, ?2, ?3, 'tail', 'tail', x'01', zeroblob(32), ?1, 1, 1)",
        params![taskrun_id.as_bytes(), event_id.as_bytes(), command_id.as_bytes()],
    )
    .unwrap();
    let snapshot_digest: Vec<u8> = tx
        .query_row(
            "SELECT snapshot_integrity_digest FROM aggregate_state_snapshots
             WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        tx.execute(
            "UPDATE aggregate_state_snapshots SET snapshot_integrity_digest = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            params![snapshot_digest, taskrun_id.as_bytes()],
        )
        .is_err()
    );
    assert!(
        load_unauthenticated_replay_projection(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            taskrun_id.as_bytes()
        )
        .is_err()
    );
    tx.execute("UPDATE aggregate_streams SET last_event_id = zeroblob(16) WHERE aggregate_type = 1 AND aggregate_id = ?1", [taskrun_id.as_bytes()]).unwrap();
    assert!(
        load_unauthenticated_replay_projection(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            taskrun_id.as_bytes()
        )
        .is_err()
    );
}
