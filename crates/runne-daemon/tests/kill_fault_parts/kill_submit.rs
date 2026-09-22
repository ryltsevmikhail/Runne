// Kill-and-replay fault scenario body (included into `kill_fault_submit.rs`).

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigkill_during_in_flight_submit_converges_exactly_once_on_retry() {
    let _process_guard = KILL_FAULT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let executable = owner_private::ControlledExecutable::copy_from(env!("CARGO_BIN_EXE_runned"));
    let spec = ProtectedBundledRuntimeLaunchSpec::new(
        executable.path(),
        &temporary.path().join("runtime"),
    )
    .expect("protected launch spec");

    // ── First launch: complete first activation and connect ────────────
    let mut first = DevelopmentBundledRuntimeLauncher::new()
        .launch(&spec)
        .expect("initial protected runtime");
    let first_client = first
        .take_runtime_profile()
        .expect("initial profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("initial protected session");
    let origin = first_client.test_origin();

    seed_project_workspace(&first_client, &origin).await;

    // ── Submit with SIGKILL at a random point in flight ─────────────────
    let identity = CommandIdentity::new(
        *SUBMIT_COMMAND_ID,
        "kill-fault-submit",
    )
    .expect("identity");
    let request = SubmitTaskRunRequest::new(
        identity,
        *CONVERSATION_ID,
        *WORKSPACE_ID,
    );

    // Random delay between request fire and SIGKILL: 0–30 ms spans the
    // pre-commit, mid-commit and post-commit/ACK windows without flaky
    // synchronization.
    let mut delay_bytes = [0_u8; 2];
    OsRng.fill_bytes(&mut delay_bytes);
    let kill_delay = Duration::from_millis(u64::from(u16::from_le_bytes(delay_bytes)) % 31);

    let in_flight = tokio::spawn({
        let client = first_client.clone();
        let request = request.clone();
        async move { client.submit_task_run(request).await }
    });
    tokio::time::sleep(kill_delay).await;
    let pid = first.test_owned_child_id();
    // SAFETY: `pid` is the exact owned daemon child; SIGKILL is the fault
    // being injected. Reaped via `wait_for_exit` below.
    let killed = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    assert_eq!(killed, 0, "SIGKILL must reach the owned daemon process");

    let ack_before_kill = in_flight.await.expect("submit task must join");
    assert_eq!(
        first
            .wait_for_exit(Duration::from_secs(5))
            .expect("reap killed child"),
        BundledRuntimeProcessStatus::Exited,
        "daemon must be dead after SIGKILL"
    );
    drop(first_client);
    drop(first);

    // ── Relaunch on the same durable store and reconcile ────────────────
    let mut second = DevelopmentBundledRuntimeLauncher::new()
        .launch(&spec)
        .expect("relaunch after SIGKILL");
    let second_client = second
        .take_runtime_profile()
        .expect("relaunch profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("relaunch protected session");

    let retry = second_client
        .submit_task_run(request)
        .await
        .expect("retry after kill must commit or replay the receipt");

    // Exactly one durable batch with one identity.
    let task_runs = second_client.list_task_runs().await.expect("list after restart");
    let mine: Vec<_> = task_runs
        .iter()
        .filter(|run| run.task_run_id() == retry.task_run_id())
        .collect();
    assert_eq!(mine.len(), 1, "exactly one TaskRun for the retried identity");
    assert_eq!(mine[0].state(), runne_runtime_client::TaskRunState::Queued);
    assert_eq!(retry.stream_version(), 2, "submit commits exactly two events");

    // Convergence: whatever the killed first attempt observed (an ack or a
    // transport failure), the durable outcome is identical.
    if let Ok(ack) = ack_before_kill {
        assert_eq!(
            ack.task_run_id(),
            retry.task_run_id(),
            "killed attempt and retry must agree on the committed identity"
        );
        assert_eq!(ack.stream_version(), retry.stream_version());
    }

    second
        .request_graceful_stop()
        .expect("authenticated shutdown of the relaunched daemon");
    assert_eq!(
        second
            .wait_for_exit(Duration::from_secs(5))
            .expect("relaunch exit"),
        BundledRuntimeProcessStatus::Exited
    );
}

/// Seeds one project and one workspace through the running daemon's HTTP
/// surface so the submit has valid aggregate roots.
async fn seed_project_workspace(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    _origin: &str,
) {
    use runne_runtime_client::{CreateProjectRequest, CreateWorkspaceRequest};

    let project_request = CreateProjectRequest::new(
        command_identity(0xf1, "kill-fault-project"),
        *PROJECT_ID,
        "kill fault project",
    )
    .expect("project request");
    let project = client
        .create_project(project_request)
        .await
        .expect("seed project");
    assert_eq!(project.new_version(), 1);
    let workspace_request = CreateWorkspaceRequest::new(
        command_identity(0xf2, "kill-fault-workspace"),
        *PROJECT_ID,
        *WORKSPACE_ID,
        "kill fault workspace",
    )
    .expect("workspace request");
    let workspace = client
        .create_workspace(workspace_request)
        .await
        .expect("seed workspace");
    assert_eq!(workspace.new_version(), 1);
}

fn command_identity(low: u8, key: &'static str) -> CommandIdentity {
    // Fresh v7 command id per (low, key) pair: fixed UUIDs fail server-side
    // invalid_command_id validation; identity binding across attempt/retry is
    // preserved by the caller cloning the request before the kill.
    let _ = low;
    CommandIdentity::new(CanonicalId::now_v7(), key).expect("identity")
}
