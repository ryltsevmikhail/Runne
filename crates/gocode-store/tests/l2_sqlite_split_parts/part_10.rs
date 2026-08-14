use gocode_store::codec::StoreCodec;

#[test]
fn migrated_v16_and_v17_taskruns_refresh_both_snapshot_projections_on_queue() {
    for (marker, taskrun) in [
        (16, "018f2e3a-7000-7000-8000-000000000401"),
        (17, "018f2e3a-7000-7000-8000-000000000411"),
    ] {
        let db_path = temp_db_path(&format!("v{marker}-refresh"));
        cleanup_db(&db_path);
        let taskrun_id: TaskRunId = taskrun.parse().unwrap();
        seed_legacy_taskrun(&db_path, taskrun_id, marker);
        let (_store, service) = open_service(&db_path);
        let before = snapshot_row(&db_path, taskrun_id);
        assert_eq!(before.0, 1, "V{marker} baseline");
        service
            .queue_task_run(
                &make_context(marker as u16),
                QueueTaskRunInput {
                    taskrun_id,
                    expected_version: 1,
                },
            )
            .unwrap();
        let after = snapshot_row(&db_path, taskrun_id);
        assert_eq!(after.0, 2, "V{marker} append head");
        assert_ne!(after.1, before.1, "V1 projection must refresh");
        assert_ne!(after.2, before.2, "promotion projection must refresh");
        assert_ne!(after.3, before.3, "bound snapshot digest must refresh");
        cleanup_db(&db_path);
    }
}

fn seed_legacy_taskrun(db_path: &str, taskrun_id: TaskRunId, marker: i64) {
    let connection = gocode_store::schema::open_with_pragmas(db_path).unwrap();
    gocode_store::schema::apply_migrations_through_v16_for_test(&connection).unwrap();
    let event_id: EventId = if marker == 16 {
        "018f2e3a-7000-7000-8000-000000000402".parse().unwrap()
    } else {
        "018f2e3a-7000-7000-8000-000000000412".parse().unwrap()
    };
    let command_id: CommandId = if marker == 16 {
        "018f2e3a-7000-7000-8000-000000000403".parse().unwrap()
    } else {
        "018f2e3a-7000-7000-8000-000000000413".parse().unwrap()
    };
    let event = gocode_domain::event::EventEnvelope::from_parts(
        event_id, gocode_domain::id::AggregateId::TaskRun(taskrun_id),
        gocode_domain::id::AggregateId::TaskRun(taskrun_id), None, command_id,
        IdempotencyKey::new(format!("legacy-v{marker}")).unwrap(), 1,
        Actor::new("legacy-v18-refresh").unwrap(), Sensitivity::Public,
        gocode_domain::task_run::TaskRunEvent::TaskRunCreated, 1,
        gocode_domain::timestamp::Timestamp::from_unix_micros(1),
        gocode_domain::id::IntegrityDigest::from_bytes([0; 32]),
    );
    let payload = gocode_store::codec::TaskRunEventCodec.encode(event.payload()).unwrap();
    let digest = gocode_store::integrity::compute_integrity_digest_with_global_position(&event, 1, &payload).unwrap();
    connection.execute("INSERT INTO aggregate_streams (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) VALUES (1, ?1, 1, ?2, 1, 1)", rusqlite::params![taskrun_id.as_bytes(), event_id.as_bytes()]).unwrap();
    connection.execute("INSERT INTO events (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile) VALUES (?1, 1, ?2, 1, 1, 1, 0, 1, NULL, ?3, ?4, ?5, ?6, ?7, ?2, 1, 1)", rusqlite::params![event_id.as_bytes(), taskrun_id.as_bytes(), command_id.as_bytes(), event.idempotency_key().as_str().as_bytes(), event.actor().as_str().as_bytes(), payload, digest.as_bytes()]).unwrap();
    connection
        .execute(
            "UPDATE event_log_state SET next_global_position = 2 WHERE singleton = 1",
            [],
        )
        .unwrap();
    if marker == 17 {
        gocode_store::schema::apply_migrations_through_v17_for_test(&connection).unwrap();
    }
}

fn snapshot_row(db_path: &str, taskrun_id: TaskRunId) -> (i64, Vec<u8>, Vec<u8>, Vec<u8>) {
    rusqlite::Connection::open(db_path).unwrap().query_row(
        "SELECT aggregate_version, projection_digest, promotion_projection_digest, snapshot_integrity_digest
         FROM aggregate_state_snapshots WHERE aggregate_type = 1 AND aggregate_id = ?1",
        [taskrun_id.as_bytes()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap()
}
