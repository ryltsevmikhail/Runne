use runne_application::commands::CommandOutcome;
use runne_application::commands::CreateTaskRunInput;
use runne_application::errors::ApplicationError;
use runne_application::ports::{
    EventStore, ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error,
    StorageFailureKind,
};
use runne_domain::event::{Actor, EventEnvelope, Sensitivity};
use runne_domain::id::{
    AggregateId, ConversationId, EventId, IntegrityDigest, ProjectId, WorkspaceId,
};
use runne_domain::task_run::TaskRunEvent;
use runne_domain::timestamp::Timestamp;
use runne_store::codec::{CommandOutcomeCodec, StoreCodec, TaskRunEventCodec};
use runne_store::integrity::compute_integrity_digest_with_global_position;
use rusqlite::params;

use super::fence::create_task_run;
use super::support::*;

pub(super) fn eligible_project(database: &Database, tail: u8) -> runne_domain::id::TaskRunId {
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let taskrun_id = create_task_run(database, tail);
    database
        .connection()
        .execute(
            "UPDATE workspaces SET live = 0 WHERE workspace_id = ?1",
            [WORKSPACE],
        )
        .unwrap();
    taskrun_id
}

fn delete(database: &Database, tail: u8) -> Result<u64, Error> {
    database.repository().delete_project(
        "owner",
        command(tail),
        &key("integrity-delete"),
        ProjectId::from_bytes(PROJECT),
        3,
    )
}

#[test]
fn missing_origin_receipt_fails_closed() {
    let database = Database::new("pw-missing-origin");
    let taskrun_id = eligible_project(&database, 43);
    let connection = database.connection();
    connection
        .execute(
            "DELETE FROM command_receipts WHERE command_id = ?1",
            [command(43).as_bytes()],
        )
        .unwrap();
    assert_ne!(taskrun_id.as_bytes(), &[0; 16]);
    assert_eq!(delete(&database, 44), Err(Error::InvariantViolation));
}

#[test]
fn missing_authoritative_lineage_fails_closed() {
    let database = Database::new("pw-missing-lineage");
    let taskrun_id = eligible_project(&database, 53);
    database
        .connection()
        .execute(
            "DELETE FROM task_run_workspace_lineage WHERE taskrun_id = ?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    assert_eq!(delete(&database, 54), Err(Error::InvariantViolation));
}

#[test]
fn direct_duplicate_lookup_rejects_deleted_lineage() {
    let database = Database::new("pw-direct-duplicate-missing-lineage");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let taskrun_id = create_task_run(&database, 57);
    database
        .connection()
        .execute(
            "DELETE FROM task_run_workspace_lineage WHERE taskrun_id = ?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();

    let duplicate = database.task_runs().create_task_run(
        &task_context(57, "task-create"),
        CreateTaskRunInput {
            conversation_id: ConversationId::from_bytes(command(0x31).into_bytes()),
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
        },
    );
    assert_eq!(
        duplicate,
        Err(ApplicationError::StorageFailed(
            StorageFailureKind::IntegrityViolation
        ))
    );
}

#[test]
fn corrupt_direct_origin_cannot_hide_missing_lineage() {
    let database = Database::new("pw-corrupt-origin-missing-lineage");
    let taskrun_id = eligible_project(&database, 55);
    let connection = database.connection();
    connection
        .execute(
            "DELETE FROM task_run_workspace_lineage WHERE taskrun_id = ?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE command_receipts SET command_outcome = x'0001'
             WHERE command_id = ?1",
            [command(55).as_bytes()],
        )
        .unwrap();
    assert_eq!(delete(&database, 56), Err(Error::InvariantViolation));
}

#[test]
fn corrupt_scope_cannot_hide_a_taskrun_stream_without_lineage() {
    let database = Database::new("pw-corrupt-scope-missing-lineage");
    let taskrun_id = eligible_project(&database, 58);
    let connection = database.connection();
    connection
        .execute(
            "DELETE FROM task_run_workspace_lineage WHERE taskrun_id = ?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE command_receipts SET idempotency_scope_bytes = x'0001'
             WHERE command_id = ?1",
            [command(58).as_bytes()],
        )
        .unwrap();
    assert_eq!(delete(&database, 59), Err(Error::InvariantViolation));
}

#[test]
fn direct_origin_requires_exact_initial_outcome_version() {
    let database = Database::new("pw-direct-origin-version");
    let taskrun_id = eligible_project(&database, 60);
    let invalid = CommandOutcomeCodec
        .encode(&CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version: 2,
        })
        .unwrap();
    database
        .connection()
        .execute(
            "UPDATE command_receipts SET command_outcome = ?1 WHERE command_id = ?2",
            rusqlite::params![invalid, command(60).as_bytes()],
        )
        .unwrap();
    assert_eq!(delete(&database, 61), Err(Error::InvariantViolation));
}

#[test]
fn lineage_origin_command_must_match_first_taskrun_event() {
    let database = Database::new("pw-first-event-command");
    let taskrun_id = eligible_project(&database, 62);
    let original = database.store.load_task_run(taskrun_id).unwrap().events[0].clone();
    let replacement = command(0x7a);
    let payload_bytes = TaskRunEventCodec.encode(original.payload()).unwrap();
    let position: i64 = database
        .connection()
        .query_row(
            "SELECT global_position FROM events
             WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let changed = EventEnvelope::from_parts(
        *original.event_id(),
        original.aggregate_id().clone(),
        original.correlation_id().clone(),
        original.causation_id().copied(),
        replacement,
        original.idempotency_key().clone(),
        original.schema_version(),
        original.actor().clone(),
        *original.sensitivity(),
        original.payload().clone(),
        original.sequence(),
        *original.timestamp(),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_with_global_position(&changed, position, &payload_bytes).unwrap();
    database
        .connection()
        .execute(
            "UPDATE events SET command_id = ?1, integrity_digest = ?2
             WHERE aggregate_type = 1 AND aggregate_id = ?3 AND sequence = 1",
            params![
                replacement.as_bytes(),
                digest.as_bytes(),
                taskrun_id.as_bytes()
            ],
        )
        .unwrap();
    assert_eq!(delete(&database, 63), Err(Error::InvariantViolation));
}

#[test]
fn stale_event_digest_fails_closed_before_terminal_classification() {
    let database = Database::new("pw-stale-digest");
    let taskrun_id = eligible_project(&database, 45);
    database
        .connection()
        .execute(
            "UPDATE events SET integrity_digest = zeroblob(32)
             WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    assert_eq!(delete(&database, 46), Err(Error::InvariantViolation));
}

#[test]
fn valid_digest_with_invalid_taskrun_history_fails_canonical_replay() {
    let database = Database::new("pw-invalid-history");
    let taskrun_id = eligible_project(&database, 47);
    let connection = database.connection();
    let global_position: i64 = connection
        .query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let timestamp = Timestamp::from_unix_micros(9_999_999_999);
    let event_id = EventId::from_bytes(command(0x70).into_bytes());
    let idempotency_key = key("duplicate-creation");
    let actor = Actor::new("integrity-test").unwrap();
    let payload = TaskRunEvent::TaskRunCreated;
    let payload_bytes = TaskRunEventCodec.encode(&payload).unwrap();
    let envelope = EventEnvelope::from_parts(
        event_id,
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        None,
        command(0x71),
        idempotency_key.clone(),
        1,
        actor.clone(),
        Sensitivity::Public,
        payload,
        2,
        timestamp,
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_with_global_position(&envelope, global_position, &payload_bytes)
            .unwrap();
    connection
        .execute(
            "INSERT INTO events
        (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
         sensitivity, schema_version, causation_id, command_id, idempotency_key, actor,
         payload, integrity_digest, correlation_id, correlation_type, integrity_profile)
        VALUES (?1, 1, ?2, 2, ?3, ?4, 0, 1, NULL, ?5, ?6, ?7, ?8, ?9, ?2, 1, 1)",
            params![
                event_id.as_bytes(),
                taskrun_id.as_bytes(),
                global_position,
                timestamp.as_unix_micros(),
                command(0x71).as_bytes(),
                idempotency_key.as_str().as_bytes(),
                actor.as_str().as_bytes(),
                payload_bytes,
                digest.as_bytes()
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE aggregate_streams SET current_version = 2,
        last_event_id = ?1, last_timestamp = ?2 WHERE aggregate_type = 1 AND aggregate_id = ?3",
            params![
                event_id.as_bytes(),
                timestamp.as_unix_micros(),
                taskrun_id.as_bytes()
            ],
        )
        .unwrap();
    assert_eq!(delete(&database, 48), Err(Error::InvariantViolation));
}
