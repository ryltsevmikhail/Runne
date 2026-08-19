
#[test]
fn test_correlation_metadata_is_persisted_and_corruption_fails_closed() {
    let database = validated_reopen::ValidatedTestDatabase::new("correlation-metadata");
    let db_path = database.path().to_owned();
    cleanup_db(&db_path);

    let (store, identity) = validated_reopen::initialize_store(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    validated_reopen::seed_canonical_workspace(&store, "test-principal", make_ws_id());
    let svc = TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        store.runtime_authority_id().clone(),
    );
    let outcome = svc
        .create_task_run(
            &make_context(1),
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap();
    let taskrun_id = match outcome {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    let conn = validated_reopen_store::open_validated_writer(&db_path, identity).unwrap();
    let (correlation_id, correlation_type, integrity_profile): (Vec<u8>, i64, i64) = conn
        .query_row(
            "SELECT correlation_id, correlation_type, integrity_profile
             FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1",
            rusqlite::params![taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(correlation_id, taskrun_id.as_bytes());
    assert_eq!(correlation_type, 1);
    assert_eq!(integrity_profile, 1);

    conn.execute(
        "UPDATE events SET correlation_type = 2
         WHERE aggregate_type = 1 AND aggregate_id = ?1",
        rusqlite::params![taskrun_id.as_bytes()],
    )
    .unwrap();
    assert!(matches!(
        store.load_task_run(taskrun_id),
        Err(EventStoreError::CorruptData)
    ));

    conn.execute(
        "UPDATE events SET correlation_type = 1, integrity_profile = 2
         WHERE aggregate_type = 1 AND aggregate_id = ?1",
        rusqlite::params![taskrun_id.as_bytes()],
    )
    .unwrap();
    assert!(matches!(
        store.load_task_run(taskrun_id),
        Err(EventStoreError::CorruptData)
    ));

    conn.execute(
        "UPDATE events SET integrity_profile = 1
         WHERE aggregate_type = 1 AND aggregate_id = ?1",
        rusqlite::params![taskrun_id.as_bytes()],
    )
    .unwrap();
    assert!(
        conn.execute(
            "UPDATE events SET correlation_id = x'00'
             WHERE aggregate_type = 1 AND aggregate_id = ?1",
            rusqlite::params![taskrun_id.as_bytes()],
        )
        .is_err()
    );
    assert!(store.load_task_run(taskrun_id).is_ok());

    conn.execute(
        "UPDATE events SET correlation_id = zeroblob(16)
         WHERE aggregate_type = 1 AND aggregate_id = ?1",
        rusqlite::params![taskrun_id.as_bytes()],
    )
    .unwrap();
    assert!(matches!(
        store.load_task_run(taskrun_id),
        Err(EventStoreError::CorruptData)
    ));

    cleanup_db(&db_path);
}

// ── Test 4: Dedup — repeat command returns original result ────────────────

#[test]
fn test_dedup_repeat_command() {
    let db_path = temp_db_path("dedup");
    cleanup_db(&db_path);

    let (store, svc) = open_service(&db_path);

    let ctx = make_context(1);
    let input = CreateTaskRunInput {
        conversation_id: make_conv_id(),
        workspace_id: make_ws_id(),
    };

    // First call
    let first = svc.create_task_run(&ctx, input.clone()).unwrap();
    let tr_id = match first {
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version,
        } => {
            assert_eq!(new_version, 1);
            taskrun_id
        }
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Repeat with same context → dedup, same result
    let second = svc.create_task_run(&ctx, input).unwrap();
    match second {
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version,
        } => {
            assert_eq!(taskrun_id, tr_id, "dedup should return same taskrun_id");
            assert_eq!(new_version, 1, "dedup should return same version");
        }
        other => panic!("expected TaskRunCreated (dedup), got {:?}", other),
    }

    // Verify events NOT duplicated: version should still be 1
    let stream = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 1, "events should not be duplicated");
    assert_eq!(stream.events.len(), 1);

    // Queue dedup
    let ctx_q = make_context(2);
    svc.queue_task_run(
        &ctx_q,
        QueueTaskRunInput {
            taskrun_id: tr_id,
            expected_version: 1,
        },
    )
    .unwrap(); // version now 2

    // Repeat queue with same context → dedup
    let retry = svc
        .queue_task_run(
            &ctx_q,
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();
    assert!(matches!(
        retry,
        CommandOutcome::TaskRunQueued { new_version: 2, .. }
    ));

    // Check stream: should still have 2 events, not 3
    let stream2 = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream2.current_version, 2);
    assert_eq!(stream2.events.len(), 2);

    cleanup_db(&db_path);
}

// ── Test 5: VersionConflict — stale expected_version ─────────────────────

#[test]
fn test_version_conflict() {
    let db_path = temp_db_path("version-conflict");
    cleanup_db(&db_path);

    let (store, svc) = open_service(&db_path);

    // Create (version 1)
    let outcome = svc
        .create_task_run(
            &make_context(1),
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap();
    let tr_id = match outcome {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Queue at version 1 → success (version becomes 2)
    svc.queue_task_run(
        &make_context(2),
        QueueTaskRunInput {
            taskrun_id: tr_id,
            expected_version: 1,
        },
    )
    .unwrap();

    // Queue again at version 1 (stale) → VersionConflict
    let err = svc
        .queue_task_run(
            &make_context(3),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap_err();

    assert!(
        matches!(
            err,
            ApplicationError::VersionConflict {
                expected: 1,
                actual: 2
            }
        ),
        "expected VersionConflict, got {:?}",
        err,
    );

    // Verify stream was NOT modified (still version 2)
    let stream = store.load_task_run(tr_id).unwrap();
    assert_eq!(
        stream.current_version, 2,
        "stream should be unchanged after conflict"
    );
    assert_eq!(stream.events.len(), 2);

    cleanup_db(&db_path);
}
