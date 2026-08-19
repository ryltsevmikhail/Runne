
// ── Test 9: WAL reopen — data survives close/reopen ──────────────────────

#[test]
fn test_wal_reopen_data_intact() {
    let database = validated_reopen::ValidatedTestDatabase::new("wal-reopen");
    let db_path = database.path().to_owned();
    cleanup_db(&db_path);

    // Phase 1: create + queue + admit
    let tr_id = {
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
        let tr_id = match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("expected TaskRunCreated, got {:?}", other),
        };

        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();

        svc.admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap();

        (tr_id, identity)
    }; // store dropped

    // Phase 2: reopen and verify data intact (WAL mode verified via PRAGMA in Test 1) and continue from version 3
    let store = validated_reopen::reopen_store(
        &db_path,
        tr_id.1,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let svc = TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        store.runtime_authority_id().clone(),
    );

    // Load stream — should have 3 events
    let stream = store.load_task_run(tr_id.0).unwrap();
    assert_eq!(stream.current_version, 3);
    assert_eq!(stream.events.len(), 3);

    // Verify replay works
    let agg = TaskRun::replay(&stream.events).unwrap();
    assert!(!agg.state().is_terminal());

    // Continue: start attempt (version 3 → 4)
    let outcome = svc
        .start_attempt(
            &make_context(4),
            StartAttemptInput {
                taskrun_id: tr_id.0,
                expected_version: 3,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::AttemptStarted { new_version: 4, .. }
    ));

    // Complete (version 4 → 5)
    let outcome = svc
        .complete_task_run(
            &make_context(5),
            CompleteTaskRunInput {
                taskrun_id: tr_id.0,
                result: TerminalResult::Success,
                expected_version: 4,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunCompleted { new_version: 5, .. }
    ));

    // Final check via a fresh open: 5 events total
    let store3 = validated_reopen::reopen_store(
        &db_path,
        tr_id.1,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let stream = store3.load_task_run(tr_id.0).unwrap();
    assert_eq!(stream.current_version, 5);
    assert_eq!(stream.events.len(), 5);

    cleanup_db(&db_path);
}

// ── Test 10: Schema mismatch — verify fail-closed behavior ────────────────

#[test]
fn test_schema_mismatch_fail_closed() {
    let database = validated_reopen::ValidatedTestDatabase::new("schema-mismatch");
    let db_path = database.path().to_owned();
    cleanup_db(&db_path);

    // Phase 1: create a valid store with data
    let (_tr_id, identity): (TaskRunId, validated_reopen::MainDatabaseIdentity) = {
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
        (taskrun_id, identity)
    }; // store dropped

    // Phase 2: corrupt the DB by dropping the events table
    {
        let conn = validated_reopen_store::open_validated_writer(&db_path, identity).unwrap();
        // Drop the events table — integrity_check checks internal b-tree
        // integrity, not application table presence, so reopen won't fail.
        conn.execute_batch("DROP TABLE events;").unwrap();
    }

    // Phase 3: the exact schema catalog gate rejects the missing table before
    // any store handle is admitted.
    let result = validated_reopen::reopen_store(
        &db_path,
        identity,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    );
    assert!(matches!(
        result,
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    ));

    cleanup_db(&db_path);
}
