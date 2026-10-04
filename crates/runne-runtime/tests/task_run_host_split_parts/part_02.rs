#[tokio::test(flavor = "current_thread")]
async fn dispatches_and_reconstructs_the_complete_durable_lifecycle() {
    let mut runtime = TestRuntime::start();

    let create_context = command_context(1, "create-1");
    let created = runtime
        .host
        .create_task_run(create_context.clone(), create_command())
        .await
        .unwrap();
    assert_eq!(created.new_version, 1);
    assert_eq!(created.kind, TaskRunCommandAckKind::Created);

    let duplicate = runtime
        .host
        .create_task_run(create_context, create_command())
        .await
        .unwrap();
    assert_eq!(duplicate, created);

    let taskrun_id = created.taskrun_id;
    let queued = runtime
        .host
        .queue_task_run(
            command_context(2, "queue-1"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(queued.new_version, 2);
    assert_eq!(queued.kind, TaskRunCommandAckKind::Queued);

    let admitted = runtime
        .host
        .admit_task_run(
            command_context(3, "admit-1"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(admitted.new_version, 3);
    assert_eq!(admitted.kind, TaskRunCommandAckKind::Admitted);

    let started = runtime
        .host
        .start_attempt(
            command_context(4, "attempt-1"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 3,
            },
        )
        .await
        .unwrap();
    let attempt_id = match started.kind {
        TaskRunCommandAckKind::AttemptStarted { attempt_id } => attempt_id,
        other => panic!("expected attempt acknowledgement, got {other:?}"),
    };
    assert_eq!(started.new_version, 4);
    let running = runtime.host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(running.state, CanonicalTaskRunState::Running);
    assert_eq!(running.active_attempt_id, Some(attempt_id));

    let completed = runtime
        .host
        .complete_task_run(
            command_context(5, "complete-1"),
            CompleteTaskRunCommand {
                taskrun_id,
                expected_version: 4,
                result: CanonicalTerminalResult::Success,
            },
        )
        .await
        .unwrap();
    assert_eq!(completed.new_version, 5);
    assert_eq!(
        completed.kind,
        TaskRunCommandAckKind::Completed {
            result: CanonicalTerminalResult::Success,
        }
    );

    let snapshot = runtime.host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(snapshot.taskrun_id, taskrun_id);
    assert_eq!(snapshot.state, CanonicalTaskRunState::Succeeded);
    assert_eq!(snapshot.stream_version, 5);
    assert_eq!(snapshot.active_attempt_id, None);
    assert_eq!(
        snapshot.terminal_result,
        Some(CanonicalTerminalResult::Success)
    );

    let stream = runtime.store.load_task_run(taskrun_id).unwrap();
    assert_eq!(stream.events.len(), 5);
    assert!(
        stream
            .events
            .iter()
            .all(|event| event.actor().as_str() == "runne-cli")
    );

    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn maps_idempotency_and_expected_version_conflicts_without_mutation() {
    let mut runtime = TestRuntime::start();
    let created = runtime
        .host
        .create_task_run(command_context(10, "create-conflict"), create_command())
        .await
        .unwrap();
    let taskrun_id = created.taskrun_id;

    runtime
        .host
        .queue_task_run(
            command_context(11, "shared-queue-key"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await
        .unwrap();

    let idempotency_conflict = runtime
        .host
        .queue_task_run(
            command_context(12, "shared-queue-key"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 3,
            },
        )
        .await;
    assert_eq!(idempotency_conflict, Err(TaskRunHostError::Conflict));

    let stale_version = runtime
        .host
        .admit_task_run(
            command_context(13, "stale-admit"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await;
    assert_eq!(stale_version, Err(TaskRunHostError::Conflict));

    let snapshot = runtime.host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(snapshot.state, CanonicalTaskRunState::Queued);
    assert_eq!(snapshot.stream_version, 2);

    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn maps_missing_queries_and_reconstructs_after_store_reopen() {
    let mut runtime = TestRuntime::start();
    let missing = MISSING_TASKRUN_ID.parse::<TaskRunId>().unwrap();
    assert_eq!(
        runtime.host.get_task_run(missing).await,
        Err(TaskRunHostError::NotFound)
    );

    let created = runtime
        .host
        .create_task_run(command_context(20, "create-reopen"), create_command())
        .await
        .unwrap();
    let taskrun_id = created.taskrun_id;
    runtime
        .host
        .queue_task_run(
            command_context(21, "queue-reopen"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await
        .unwrap();

    runtime.shutdown().await;
    drop(runtime.host);
    drop(runtime.store);

    let reopened_store = validated_reopen::reopen_store(
        &runtime.database_path,
        runtime.identity,
        runtime.authority.clone(),
        available_guard(),
    )
    .unwrap();
    let (reopened_handle, mut reopened_controller) =
        start_runtime(reopened_store.clone(), runtime.authority.clone());
    let reopened_host = RuntimeTaskRunHost::new(reopened_handle, reopened_store.clone());
    let snapshot = reopened_host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(snapshot.state, CanonicalTaskRunState::Queued);
    assert_eq!(snapshot.stream_version, 2);
    assert_eq!(snapshot.active_attempt_id, None);
    assert_eq!(snapshot.terminal_result, None);

    let outcome = reopened_controller
        .shutdown(ShutdownMode::Graceful {
            timeout: Duration::from_secs(5),
        })
        .await;
    assert_eq!(outcome, ShutdownOutcome::Quiesced);
    assert_eq!(
        reopened_controller.wait_terminated().await,
        ShutdownOutcome::Quiesced
    );
    drop(reopened_host);
    drop(reopened_store);
}

const PROVIDER_MARKER: &str = "registered-provider-output";

struct MarkerGuard;

impl ProhibitedContentPort for MarkerGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(
            if bytes
                .windows(PROVIDER_MARKER.len())
                .any(|window| window == PROVIDER_MARKER.as_bytes())
            {
                ContentDisposition::Prohibited { policy_epoch: 1 }
            } else {
                ContentDisposition::Allowed { policy_epoch: 1 }
            },
        )
    }
}

struct ProviderInputRejectingGuard;
