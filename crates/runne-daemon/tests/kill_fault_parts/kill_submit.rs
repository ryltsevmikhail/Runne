// Kill-and-replay fault scenario body (included into `kill_fault_submit.rs`).
//
// Deterministic kill-point handshake: the commit gate file is written by the
// real daemon's store immediately after `tx.commit()` and before the command
// host answers, so awaiting the marker pins the SIGKILL inside the
// post-commit/pre-ACK window on every run.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigkill_between_durable_commit_and_ack_converges_exactly_once_on_retry() {
    let _process_guard = KILL_FAULT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let gate = temporary.path().join("commit-gate.marker");
    let release = temporary.path().join("commit-gate.release");
    // Armed before launch so the first durable commit holds at the boundary.
    // SAFETY: single-threaded test harness lock serializes all launches; no
    // other thread reads the environment concurrently.
    unsafe { std::env::set_var("RUNNE_TEST_COMMIT_GATE_FILE", &gate) };
    unsafe { std::env::set_var("RUNNE_TEST_COMMIT_GATE_RELEASE", &release) };
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

    seed_project_workspace(&first_client).await;

    // ── Submit; kill exactly between durable commit and ACK ─────────────
    let identity = CommandIdentity::new(*SUBMIT_COMMAND_ID, "kill-fault-submit").expect("identity");
    let request = SubmitTaskRunRequest::new(identity, *CONVERSATION_ID, *WORKSPACE_ID);

    let in_flight = tokio::spawn({
        let client = first_client.clone();
        let request = request.clone();
        async move { client.submit_task_run(request).await }
    });

    // The marker exists only after the daemon's SQLite tx.commit() for the
    // Created+Queued batch; reaching it is the deterministic kill-point proof.
    wait_for_commit_gate(&gate);

    // The acknowledgement must not have crossed the transport yet: the
    // in-flight future is still blocked and no ready value can be observed.
    assert!(
        !in_flight.is_finished(),
        "ACK must not be delivered before the gate is observed post-commit"
    );

    let pid = first.test_owned_child_id();
    // SAFETY: `pid` is the exact owned daemon child; SIGKILL is the fault
    // being injected. Reaped via `wait_for_exit` below.
    let killed = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    assert_eq!(killed, 0, "SIGKILL must reach the owned daemon process");

    // The killed attempt never completes its ACK: the future resolves only
    // through transport teardown (an error), never with a successful submit.
    let ack_before_kill = in_flight.await.expect("submit task must join");
    assert!(
        ack_before_kill.is_err(),
        "killed attempt must not deliver a successful ACK after the kill"
    );
    assert_eq!(
        first
            .wait_for_exit(Duration::from_secs(5))
            .expect("reap killed child"),
        BundledRuntimeProcessStatus::Exited,
        "daemon must be dead after SIGKILL"
    );
    drop(first_client);
    drop(first);
    // SAFETY: same serialization argument as the arming `set_var` above.
    unsafe { std::env::remove_var("RUNNE_TEST_COMMIT_GATE_FILE") };
    unsafe { std::env::remove_var("RUNNE_TEST_COMMIT_GATE_RELEASE") };

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
        .expect("retry after kill must replay the stored receipt");

    // Exactly one durable TaskRun with the retried identity.
    let task_runs = second_client
        .list_task_runs()
        .await
        .expect("list after restart");
    let mine: Vec<_> = task_runs
        .iter()
        .filter(|run| run.task_run_id() == retry.task_run_id())
        .collect();
    assert_eq!(mine.len(), 1, "exactly one TaskRun for the retried identity");
    assert_eq!(mine[0].state(), runne_runtime_client::TaskRunState::Queued);
    assert_eq!(retry.stream_version(), 2, "receipt replay commits no new events");

    // Convergence: the committed identity outlives the killed attempt even
    // though its ACK never reached the client.
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

/// Polls for the post-commit gate marker written by the daemon's store.
fn wait_for_commit_gate(gate: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !gate.exists() {
        assert!(
            Instant::now() < deadline,
            "daemon never reached the durable commit boundary"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Seeds one project and one workspace through the running daemon's HTTP
/// surface so the submit has valid aggregate roots.
async fn seed_project_workspace(client: &runne_runtime_client::AuthenticatedRuntimeClient) {
    use runne_runtime_client::{CreateProjectRequest, CreateWorkspaceRequest};

    let project_request = CreateProjectRequest::new(
        CommandIdentity::new(CanonicalId::now_v7(), "kill-fault-project").expect("identity"),
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
        CommandIdentity::new(CanonicalId::now_v7(), "kill-fault-workspace").expect("identity"),
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
