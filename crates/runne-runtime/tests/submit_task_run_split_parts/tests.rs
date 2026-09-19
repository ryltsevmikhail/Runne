// X2 Step 4 runtime submit conformance tests. Fixtures live in `harness.rs`;
// both split parts are included into one test crate module.

#[tokio::test(flavor = "current_thread")]
async fn submit_commits_one_atomic_batch_through_the_runtime_host() {
    let mut runtime = SubmitRuntime::start();
    let ack = runtime
        .host
        .submit_task_run(command_context(1, "submit-1"), submit_command(WORKSPACE_ID))
        .await
        .expect("submit must commit through the runtime");

    assert_submitted_batch(&runtime, &ack);
    let (state, version) = query_state(&runtime, ack.taskrun_id).await;
    assert_eq!(state, CanonicalTaskRunState::Queued);
    assert_eq!(version, 2);

    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn lost_ack_duplicate_submit_replays_the_stored_receipt() {
    let mut runtime = SubmitRuntime::start();
    let context = command_context(1, "submit-1");
    let first = runtime
        .host
        .submit_task_run(context.clone(), submit_command(WORKSPACE_ID))
        .await
        .expect("first submit");
    let duplicate = runtime
        .host
        .submit_task_run(context, submit_command(WORKSPACE_ID))
        .await
        .expect("duplicate identity replays the stored ack");

    assert_eq!(first, duplicate, "identical identity replays one receipt");
    assert_submitted_batch(&runtime, &first);
    let stream = runtime.store.load_task_run(first.taskrun_id).unwrap();
    assert_eq!(stream.events.len(), 2, "duplicate must not append events");

    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn changed_payload_under_same_identity_conflicts_without_effect() {
    let mut runtime = SubmitRuntime::start();
    let context = command_context(1, "submit-1");
    let first = runtime
        .host
        .submit_task_run(context.clone(), submit_command(WORKSPACE_ID))
        .await
        .expect("first submit");

    let conflict = runtime
        .host
        .submit_task_run(context, submit_command(OTHER_WORKSPACE_ID))
        .await
        .expect_err("same identity with a different payload must conflict");
    assert_eq!(conflict, TaskRunHostError::Conflict);

    let stream = runtime.store.load_task_run(first.taskrun_id).unwrap();
    assert_eq!(stream.events.len(), 2, "conflict must not append events");
    let replayed = TaskRun::replay(&stream.events).unwrap();
    assert_eq!(replayed.state(), TaskRunState::Queued);

    // The stored receipt stays authoritative for the original payload.
    let replay = runtime
        .host
        .submit_task_run(command_context(1, "submit-1"), submit_command(WORKSPACE_ID))
        .await
        .expect("original payload still replays the stored ack");
    assert_eq!(replay, first);

    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn submitted_task_run_cancels_and_the_runtime_quiesces() {
    let mut runtime = SubmitRuntime::start();
    let ack = runtime
        .host
        .submit_task_run(command_context(1, "submit-1"), submit_command(WORKSPACE_ID))
        .await
        .expect("submit must commit");
    assert_submitted_batch(&runtime, &ack);

    let cancellation = runtime
        .host
        .request_task_run_cancellation(
            command_context(2, "cancel-1"),
            ExistingTaskRunCommand {
                taskrun_id: ack.taskrun_id,
                expected_version: 2,
            },
        )
        .await
        .expect("cancellation after submit must commit");

    assert_eq!(cancellation.taskrun_id, ack.taskrun_id);
    assert_eq!(cancellation.new_version, 3);
    assert_eq!(
        cancellation.kind,
        TaskRunCommandAckKind::CancellationRequested
    );
    let (state, _) = query_state(&runtime, ack.taskrun_id).await;
    assert_eq!(state, CanonicalTaskRunState::Cancelling);

    runtime.shutdown().await;
}
