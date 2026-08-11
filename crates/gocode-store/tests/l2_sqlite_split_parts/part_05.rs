
// ── Test 6: IdempotencyConflict — same scope+key, different fingerprint ──

#[test]
fn test_idempotency_conflict_different_fingerprint() {
    let db_path = temp_db_path("idem-conflict");
    cleanup_db(&db_path);

    let (_store, svc) = open_service(&db_path);

    // Create
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

    // Queue at version 1 with idempotency key from context(2)
    svc.queue_task_run(
        &make_context(2),
        QueueTaskRunInput {
            taskrun_id: tr_id,
            expected_version: 1,
        },
    )
    .unwrap();

    // Same idempotency_key ("test-key-2"), different CommandId and expected_version
    // → different fingerprint. Scope+key matches → IdempotencyConflict.
    let conflict_ctx = ApplicationCommandContext {
        command_id: CommandId::from_bytes([
            0x02, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x99,
        ]),
        idempotency_key: IdempotencyKey::new("test-key-2").unwrap(),
        principal_id: PrincipalId("test-principal".into()),
        actor: Actor::new("test-actor-99").unwrap(),
    };
    let err = svc
        .queue_task_run(
            &conflict_ctx,
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 3,
            },
        )
        .unwrap_err();

    assert!(
        matches!(err, ApplicationError::IdempotencyConflict { .. }),
        "expected IdempotencyConflict, got {:?}",
        err,
    );

    cleanup_db(&db_path);
}

// ── Test 7: ClockRegression — reject timestamps going backwards ──────────

#[test]
fn test_clock_regression() {
    let database = validated_reopen::ValidatedTestDatabase::new("clock-regression");
    let db_path = database.path().to_owned();
    cleanup_db(&db_path);

    let (tr_id, identity): (TaskRunId, validated_reopen::MainDatabaseIdentity) = {
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

        (tr_id, identity)
    }; // store dropped — connections closed, WAL checkpointed

    // Open DB directly and set last_timestamp to a far-future value
    {
        let conn = validated_reopen_store::open_validated_writer(&db_path, identity).unwrap();
        conn.execute(
            "UPDATE aggregate_streams SET last_timestamp = ?1",
            rusqlite::params![i64::MAX],
        )
        .unwrap();
    }

    // Reopen store and try to commit — should detect clock regression.
    // The service maps ClockRegression to StorageFailed(IntegrityViolation).
    let store = validated_reopen::reopen_store(
        &db_path,
        identity,
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

    let err = svc
        .admit_task_run(
            &make_context(5),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap_err();

    assert!(
        matches!(
            err,
            ApplicationError::StorageFailed(StorageFailureKind::IntegrityViolation)
        ),
        "expected StorageFailed(IntegrityViolation) from ClockRegression, got {:?}",
        err,
    );

    cleanup_db(&db_path);
}

// ── Test 8: Two competing writers ────────────────────────────────────────

#[test]
fn test_two_competing_writers() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let database = validated_reopen::ValidatedTestDatabase::new("competing");
    let db_path = database.path().to_owned();
    cleanup_db(&db_path);

    let (tr_id, identity): (TaskRunId, validated_reopen::MainDatabaseIdentity) = {
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
            other => panic!("{other:?}"),
        };
        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();
        (tr_id, identity)
    };

    let barrier = Arc::new(Barrier::new(2));
    let db = Arc::new(db_path.clone());
    let identity = Arc::new(identity);
    let tr = Arc::new(tr_id);
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = vec![];
    for i in 0..2 {
        let db = Arc::clone(&db);
        let identity = Arc::clone(&identity);
        let tr = Arc::clone(&tr);
        let barrier = Arc::clone(&barrier);
        let results = Arc::clone(&results);
        let ctx = make_context(10 + i);
        handles.push(thread::spawn(move || {
            let store = validated_reopen::reopen_store(
                db.as_str(),
                *identity,
                RuntimeAuthorityId("test-host".into()),
                available_guard(),
            )
            .unwrap();
            let ra = store.runtime_authority_id().clone();
            let svc = TaskRunService::new(store.clone(), store.clone(), store.clone(), ra);
            barrier.wait();
            let r = svc.admit_task_run(
                &ctx,
                AdmitTaskRunInput {
                    taskrun_id: *tr,
                    expected_version: 2,
                },
            );
            results.lock().unwrap().push(r);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let res = results.lock().unwrap();
    let committed = res.iter().filter(|r| r.is_ok()).count();
    assert_eq!(committed, 1, "exactly one writer must commit, got {res:?}");

    let store = validated_reopen::reopen_store(
        &db_path,
        *identity,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let stream = store.load_task_run(*tr).unwrap();
    assert_eq!(
        stream.current_version, 3,
        "stream must have exactly 3 events"
    );
    cleanup_db(&db_path);
}
