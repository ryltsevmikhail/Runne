use super::*;
use runne_domain::event::{EventEnvelope, Sensitivity};
use runne_domain::id::{
    AggregateId, CommandId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId,
};
use runne_domain::task_run::TaskRunEvent;
use runne_domain::timestamp::Timestamp;
use runne_store::codec::{StoreCodec, TaskRunEventCodec};
use runne_store::integrity::compute_integrity_digest_with_global_position;

type ReleaseEventTestRow = (
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn released_fixture() -> (
    Database,
    TaskRunAssignmentIdentity,
    u64,
    TaskRunNoEffectReleaseRequest,
) {
    let database = Database::new("taskrun-release-integrity");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let result = submit_task_run(&database, 0x21, "release-integrity");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = result else {
        panic!()
    };
    let (node, epoch) = node_registration(&database);
    let (identity, version) = claim(&database, taskrun_id, 0x31, &node, epoch);
    let request = release_request(&database, identity.clone(), version, 0x51);
    database
        .store
        .release_taskrun_no_effect(request.clone())
        .unwrap();
    (database, identity, version, request)
}

fn mutate_valid_release_stream(database: &Database, taskrun_id: TaskRunId, mode: &str) {
    let connection = database.connection();
    let (event, global_position, timestamp, sequence, command, key, actor, cause, payload):
        ReleaseEventTestRow = connection
        .query_row(
            "SELECT e.event_id,e.global_position,e.timestamp,e.sequence,e.command_id,e.idempotency_key,e.actor,e.causation_id,e.payload FROM events e JOIN taskrun_assignment_occupations o ON o.release_event_id=e.event_id WHERE o.taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
        ).unwrap();
    let key = if mode == "key" {
        "different-idempotency-key".to_owned()
    } else {
        String::from_utf8(key).unwrap()
    };
    let cause = if mode == "cause" {
        connection
            .query_row(
                "SELECT admitted_event_id FROM taskrun_claim_receipts WHERE taskrun_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap()
    } else {
        cause
    };
    let payload = if mode == "payload" {
        TaskRunEventCodec
            .encode(&TaskRunEvent::TaskRunFailed {
                reason: "different".into(),
            })
            .unwrap()
    } else {
        payload
    };
    let id = EventId::from_bytes(event.try_into().unwrap());
    let cause = EventId::from_bytes(cause.try_into().unwrap());
    let command = CommandId::from_bytes(command.try_into().unwrap());
    let key_value = IdempotencyKey::new(key.clone()).unwrap();
    let payload_value = TaskRunEventCodec.decode(&payload).unwrap();
    let envelope = EventEnvelope::from_parts(
        id,
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        Some(cause),
        command,
        key_value,
        1,
        runne_domain::event::Actor::new(String::from_utf8(actor).unwrap()).unwrap(),
        Sensitivity::Public,
        payload_value,
        sequence as u64,
        Timestamp::from_unix_micros(timestamp),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let payload = TaskRunEventCodec.encode(envelope.payload()).unwrap();
    let digest =
        compute_integrity_digest_with_global_position(&envelope, global_position, &payload)
            .unwrap();
    connection.execute(
        "UPDATE events SET idempotency_key=?1,causation_id=?2,payload=?3,integrity_digest=?4 WHERE event_id=?5",
        rusqlite::params![key.as_bytes(),cause.as_bytes(),payload,digest.as_bytes(),id.as_bytes()],
    ).unwrap();
}

#[test]
fn duplicate_release_rejects_validly_rehashed_key_cause_and_payload_tampering() {
    for mode in ["key", "cause", "payload"] {
        let (database, identity, version, request) = released_fixture();
        mutate_valid_release_stream(&database, identity.taskrun_id, mode);
        assert_eq!(
            database.store.release_taskrun_no_effect(request),
            Err(TaskRunNoEffectReleaseError::CorruptData),
            "tampered {mode} must not replay as a duplicate",
        );
        let _ = version;
    }
}

#[test]
fn v45_admission_rejects_validly_rehashed_release_event_tampering() {
    let (database, identity, _, _) = released_fixture();
    mutate_valid_release_stream(&database, identity.taskrun_id, "key");
    let reopened = super::super::super::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    );
    assert!(
        reopened.is_err(),
        "V45 admission must reject the mismatched event key"
    );
}
