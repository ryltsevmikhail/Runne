
#[test]
fn taskrun_crash_mid_lifecycle_preserves_all_committed_events() {
    let database = validated_reopen::ValidatedTestDatabase::new("taskrun-crash-mid-lifecycle");
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

    let reopened_store = validated_reopen::reopen_store(
        &db_path,
        identity,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let reopened_service = TaskRunService::new(
        reopened_store.clone(),
        reopened_store.clone(),
        reopened_store.clone(),
        reopened_store.runtime_authority_id().clone(),
    );
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

#[test]
fn two_writers_racing_on_start_and_complete_have_exactly_one_winner_each() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let database = validated_reopen::ValidatedTestDatabase::new("start-complete-race");
    let db_path = Arc::new(database.path().to_owned());
    cleanup_db(&db_path);
    let (taskrun_id, identity) = {
        let (store, identity) = validated_reopen::initialize_store(
            db_path.as_str(),
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
        (taskrun_id, identity)
    };
    let identity = Arc::new(identity);

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
            let path = Arc::clone(&db_path);
            let identity = Arc::clone(&identity);
            handles.push(thread::spawn(move || {
                let store = validated_reopen::reopen_store(
                    path.as_str(),
                    *identity,
                    RuntimeAuthorityId("test-host".into()),
                    available_guard(),
                )
                .unwrap();
                let service = TaskRunService::new(
                    store.clone(),
                    store.clone(),
                    store.clone(),
                    store.runtime_authority_id().clone(),
                );
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
        validated_reopen::reopen_store(
            db_path.as_str(),
            *identity,
            RuntimeAuthorityId("test-host".into()),
            available_guard(),
        )
        .unwrap()
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        5
    );

    cleanup_db(&db_path);
}
