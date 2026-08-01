#[test]
fn test_clock_regression() {
    let db_path = temp_db_path("clock-regression");
    cleanup_db(&db_path);

    let tr_id: TaskRunId = {
        let (_store, svc) = open_service(&db_path);

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

        tr_id
    }; // store dropped — connections closed, WAL checkpointed

    // Open DB directly and set last_timestamp to a far-future value
    {
        let conn = gocode_store::schema::open_with_pragmas(&db_path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        conn.execute(
            "UPDATE aggregate_streams SET last_timestamp = ?1",
            rusqlite::params![i64::MAX],
        )
        .unwrap();
    }

    // Reopen store and try to commit — should detect clock regression.
    // The service maps ClockRegression to StorageFailed(IntegrityViolation).
    let (_store, svc) = open_service(&db_path);

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

    let db_path = temp_db_path("competing");
    cleanup_db(&db_path);

    let tr_id: TaskRunId = {
        let (_store, svc) = open_service(&db_path);
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
        tr_id
    };

    let barrier = Arc::new(Barrier::new(2));
    let db = Arc::new(db_path.clone());
    let tr = Arc::new(tr_id);
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = vec![];
    for i in 0..2 {
        let db = Arc::clone(&db);
        let tr = Arc::clone(&tr);
        let barrier = Arc::clone(&barrier);
        let results = Arc::clone(&results);
        let ctx = make_context(10 + i);
        handles.push(thread::spawn(move || {
            let store = StoreTransaction::open(
                &db,
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

    let (_store, _svc) = open_service(&db_path);
    let stream = _store.load_task_run(*tr).unwrap();
    assert_eq!(
        stream.current_version, 3,
        "stream must have exactly 3 events"
    );
    cleanup_db(&db_path);
}

#[test]
fn taskrun_crash_mid_lifecycle_preserves_all_committed_events() {
    let db_path = temp_db_path("taskrun-crash-mid-lifecycle");
    cleanup_db(&db_path);

    let (store, svc) = open_service(&db_path);
    let taskrun_id = match svc
        .create_task_run(
            &make_context(1),
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap()
    {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("expected TaskRunCreated, got {other:?}"),
    };
    svc.queue_task_run(
        &make_context(2),
        QueueTaskRunInput {
            taskrun_id,
            expected_version: 1,
        },
    )
    .unwrap();
    svc.admit_task_run(
        &make_context(3),
        AdmitTaskRunInput {
            taskrun_id,
            expected_version: 2,
        },
    )
    .unwrap();
    svc.start_attempt(
        &make_context(4),
        StartAttemptInput {
            taskrun_id,
            expected_version: 3,
        },
    )
    .unwrap();

    std::mem::forget(svc);
    std::mem::forget(store);

    let (reopened_store, reopened_service) = open_service(&db_path);
    let stream = reopened_store.load_task_run(taskrun_id).unwrap();
    assert_eq!(stream.current_version, 4);
    assert_eq!(stream.events.len(), 4);
    assert!(
        !TaskRun::replay(&stream.events)
            .unwrap()
            .state()
            .is_terminal()
    );

    reopened_service
        .complete_task_run(
            &make_context(5),
            CompleteTaskRunInput {
                taskrun_id,
                result: TerminalResult::Success,
                expected_version: 4,
            },
        )
        .unwrap();
    assert_eq!(
        reopened_store
            .load_task_run(taskrun_id)
            .unwrap()
            .events
            .len(),
        5
    );

    cleanup_db(&db_path);
}
