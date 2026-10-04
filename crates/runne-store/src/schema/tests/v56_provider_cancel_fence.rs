#[test]
fn v56_installs_attempt_scoped_cancel_fence_and_inherits_prior_catalogs() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 56).unwrap();
    assert_eq!(schema_marker(&connection), 56);
    assert!(v56_matches(&connection, 56).unwrap());
    assert!(v55_matches(&connection, 56).unwrap());
    let ddl: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='taskrun_provider_cancel_fences'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(ddl.contains("cancellation_version INTEGER NOT NULL CHECK(cancellation_version>0)"));
    assert!(ddl.contains("FOREIGN KEY(dispatch_attempt_id)"));
    assert!(ddl.contains("FOREIGN KEY(cancellation_event_id)"));
}

#[test]
fn v56_rejects_missing_fence_protections_and_orphan_rows() {
    for trigger in [
        "taskrun_provider_cancel_fences_immutable",
        "taskrun_provider_cancel_fences_no_delete",
        "schema_v12_fence_taskrun_provider_cancel_fences_insert",
        "schema_v12_fence_taskrun_provider_cancel_fences_update",
        "schema_v12_fence_taskrun_provider_cancel_fences_delete",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 56).unwrap();
        connection
            .execute_batch(&format!("DROP TRIGGER {trigger}"))
            .unwrap();
        assert!(!v56_matches(&connection, 56).unwrap(), "{trigger}");
    }
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 56).unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute(
            "INSERT INTO taskrun_provider_cancel_fences VALUES(?1,?2,?3,?4,1,0)",
            rusqlite::params![[1_u8; 16], [2_u8; 16], [3_u8; 16], [4_u8; 16]],
        )
        .unwrap();
    assert!(!v56_matches(&connection, 56).unwrap());
}

#[test]
fn queued_cancel_without_provider_admission_does_not_fabricate_a_remote_fence() {
    use crate::codec::{StoreCodec, TaskRunEventCodec};
    use runne_domain::id::{EventId, TaskRunId};

    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 56).unwrap();
    let taskrun = TaskRunId::from_bytes([11; 16]);
    let event = EventId::from_bytes([12; 16]);
    let payload = TaskRunEventCodec
        .encode(&runne_domain::task_run::TaskRunEvent::CancellationRequested)
        .unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams(aggregate_type,aggregate_id,current_version,last_event_id,last_timestamp,created_at)
             VALUES(1,?1,1,?2,0,0)",
            rusqlite::params![taskrun.as_bytes(), event.as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO events(event_id,aggregate_type,aggregate_id,sequence,global_position,timestamp,
             sensitivity,schema_version,causation_id,command_id,idempotency_key,actor,payload,integrity_digest,
             correlation_id,correlation_type,integrity_profile)
             VALUES(?1,1,?2,1,1,0,0,1,NULL,?3,x'01',x'02',?4,zeroblob(32),?2,1,1)",
            rusqlite::params![event.as_bytes(), taskrun.as_bytes(), [13_u8; 16], payload],
        )
        .unwrap();
    let transaction = connection.unchecked_transaction().unwrap();
    crate::provider::record_taskrun_provider_cancel_fence(&transaction, taskrun, event, 1, 0)
        .unwrap();
    transaction.commit().unwrap();
    let fences: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_provider_cancel_fences",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fences, 0);
}

#[test]
fn v56_cancel_fence_rejects_unverified_streams_even_with_matching_event_tags() {
    use crate::codec::{StoreCodec, TaskRunEventCodec};
    use runne_domain::id::{AttemptId, EventId, TaskRunId};
    use runne_domain::task_run::TaskRunEvent;

    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 56).unwrap();
    let taskrun = TaskRunId::from_bytes([21; 16]);
    let attempt = AttemptId::from_bytes([22; 16]);
    let started_event = EventId::from_bytes([23; 16]);
    let cancellation_event = EventId::from_bytes([24; 16]);
    let codec = TaskRunEventCodec;
    let started = codec
        .encode(&TaskRunEvent::AttemptStarted {
            attempt_id: attempt,
        })
        .unwrap();
    let cancelled = codec.encode(&TaskRunEvent::CancellationRequested).unwrap();
    connection.execute(
        "INSERT INTO aggregate_streams(aggregate_type,aggregate_id,current_version,last_event_id,last_timestamp,created_at)
         VALUES(1,?1,2,?2,0,0)",
        rusqlite::params![taskrun.as_bytes(), cancellation_event.as_bytes()],
    ).unwrap();
    for (id, sequence, payload) in [
        (started_event, 1_i64, started),
        (cancellation_event, 2_i64, cancelled),
    ] {
        connection.execute(
            "INSERT INTO events(event_id,aggregate_type,aggregate_id,sequence,global_position,timestamp,
             sensitivity,schema_version,causation_id,command_id,idempotency_key,actor,payload,integrity_digest,
             correlation_id,correlation_type,integrity_profile)
             VALUES(?1,1,?2,?3,?3,0,0,1,NULL,?4,x'01',x'02',?5,zeroblob(32),?2,1,1)",
            rusqlite::params![id.as_bytes(), taskrun.as_bytes(), sequence, [25_u8; 16], payload],
        ).unwrap();
    }
    assert!(
        v56_cancel_event_and_attempt_match(
            &connection,
            taskrun.as_bytes(),
            attempt.as_bytes(),
            cancellation_event.as_bytes(),
            2,
        )
        .is_err(),
        "raw event rows with a plausible start/cancel suffix are not proof without a verified integrity chain"
    );
    assert!(
        v56_cancel_event_and_attempt_match(
            &connection,
            taskrun.as_bytes(),
            AttemptId::from_bytes([26; 16]).as_bytes(),
            cancellation_event.as_bytes(),
            2,
        )
        .is_err()
    );
}
