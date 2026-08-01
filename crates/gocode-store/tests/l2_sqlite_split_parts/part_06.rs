#[test]
fn two_writers_racing_on_start_and_complete_have_exactly_one_winner_each() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let db_path = temp_db_path("start-complete-race");
    cleanup_db(&db_path);
    let taskrun_id = {
        let (_store, svc) = open_service(&db_path);
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
        taskrun_id
    };

    type RaceOperation = fn(
        &TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>,
        &ApplicationCommandContext,
        TaskRunId,
    ) -> Result<CommandOutcome, ApplicationError>;
    let race = |counter: u16, operation: RaceOperation| {
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for offset in 0..2 {
            let barrier = Arc::clone(&barrier);
            let path = db_path.clone();
            handles.push(thread::spawn(move || {
                let (store, service) = open_service(&path);
                barrier.wait();
                let result = operation(&service, &make_context(counter + offset), taskrun_id);
                drop(store);
                result
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    };

    let start = race(10, |service, context, taskrun_id| {
        service.start_attempt(
            context,
            StartAttemptInput {
                taskrun_id,
                expected_version: 3,
            },
        )
    });
    assert_eq!(
        start.iter().filter(|result| result.is_ok()).count(),
        1,
        "unexpected start race outcomes: {start:?}"
    );
    assert_eq!(
        start
            .iter()
            .filter(|result| matches!(
                result,
                Err(ApplicationError::VersionConflict {
                    expected: 3,
                    actual: 4
                })
            ))
            .count(),
        1,
        "unexpected start race outcomes: {start:?}"
    );

    let complete = race(20, |service, context, taskrun_id| {
        service.complete_task_run(
            context,
            CompleteTaskRunInput {
                taskrun_id,
                result: TerminalResult::Success,
                expected_version: 4,
            },
        )
    });
    assert_eq!(
        complete.iter().filter(|result| result.is_ok()).count(),
        1,
        "unexpected completion race outcomes: {complete:?}"
    );
    assert_eq!(
        complete
            .iter()
            .filter(|result| matches!(
                result,
                Err(ApplicationError::VersionConflict {
                    expected: 4,
                    actual: 5
                })
            ))
            .count(),
        1,
        "unexpected completion race outcomes: {complete:?}"
    );
    assert_eq!(
        open_service(&db_path)
            .0
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        5
    );

    cleanup_db(&db_path);
}

// ── Test 9: WAL reopen — data survives close/reopen ──────────────────────

#[test]
fn test_wal_reopen_data_intact() {
    let db_path = temp_db_path("wal-reopen");
    cleanup_db(&db_path);

    // Phase 1: create + queue + admit
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

        svc.admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap();

        tr_id
    }; // store dropped

    // Phase 2: reopen and verify data intact (WAL mode verified via PRAGMA in Test 1) and continue from version 3
    let (store, svc) = open_service(&db_path);

    // Load stream — should have 3 events
    let stream = store.load_task_run(tr_id).unwrap();
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
                taskrun_id: tr_id,
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
                taskrun_id: tr_id,
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
    let (store3, _svc3) = open_service(&db_path);
    let stream = store3.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 5);
    assert_eq!(stream.events.len(), 5);

    cleanup_db(&db_path);
}

// ── Test 10: Schema mismatch — verify fail-closed behavior ────────────────
