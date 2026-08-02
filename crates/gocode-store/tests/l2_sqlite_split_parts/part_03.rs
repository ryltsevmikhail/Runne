
// ── Test 2: Full lifecycle ───────────────────────────────────────────────

#[test]
fn test_full_lifecycle() {
    let db_path = temp_db_path("full-lifecycle");
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
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version,
        } => {
            assert_eq!(new_version, 1);
            taskrun_id
        }
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Queue
    let outcome = svc
        .queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunQueued { new_version: 2, .. }
    ));

    // Admit
    let outcome = svc
        .admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunAdmitted { new_version: 3, .. }
    ));

    // Start attempt
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

    // Complete
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

    cleanup_db(&db_path);
}

// ── Test 3: Replay after reopen ──────────────────────────────────────────

#[test]
fn test_replay_after_reopen() {
    let db_path = temp_db_path("replay-reopen");
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

        svc.admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap();

        svc.start_attempt(
            &make_context(4),
            StartAttemptInput {
                taskrun_id: tr_id,
                expected_version: 3,
            },
        )
        .unwrap();

        tr_id
    }; // store dropped — connections closed

    // Reopen
    let (store, _svc) = open_service(&db_path);

    // Load stream
    let stream: LoadedStream = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 4, "expected 4 events");
    assert_eq!(stream.events.len(), 4);
    assert!(stream.last_event_id.is_some());

    // Verify sequences are consecutive
    for (i, env) in stream.events.iter().enumerate() {
        assert_eq!(
            env.sequence(),
            (i + 1) as u64,
            "sequence mismatch at index {}",
            i
        );
    }

    // Replay aggregate
    let agg = TaskRun::replay(&stream.events).unwrap();
    assert!(
        !agg.state().is_terminal(),
        "aggregate should not be terminal after create+queue+admit+start"
    );

    cleanup_db(&db_path);
}
