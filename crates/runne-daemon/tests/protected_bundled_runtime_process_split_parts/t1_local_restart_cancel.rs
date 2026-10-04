use super::*;

#[path = "t1_local_restart_cancel/missing_area.rs"]
mod missing_area;
#[path = "t1_local_restart_cancel/receipt.rs"]
mod receipt;

pub(super) async fn exercise_restart_during_local_cancel(
    context: super::t1_taskrun_support::LocalTaskRunContext<'_>,
    remove_area_before_restart: bool,
) -> (
    runne_runtime_client::AuthenticatedRuntimeClient,
    runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
) {
    let super::t1_taskrun_support::LocalTaskRunContext {
        client,
        conversation_id,
        workspace_id,
        project_directory,
        database,
        runtime_root,
        executable,
        supervisor,
    } = context;
    eprintln!("RUN: protected local-command restart during durable cancellation");
    let output = project_directory.join("restart-cancel-output");
    let heartbeat = project_directory.join("restart-cancel-heartbeat");
    std::fs::write(&output, "").expect("prepare cancellation output");
    std::fs::write(&heartbeat, "").expect("prepare worker heartbeat");
    let script = format!(
        "printf 'run\\n' >> '{0}'; setsid bash -c 'trap \"\" TERM; printf child_started\\n >> \"{0}\"; while true; do printf h >> \"{1}\"; sleep 0.1; done' & child=$!; printf leader_started\\n >> '{0}'; wait \"$child\"",
        output.display(),
        heartbeat.display()
    );
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
        ".".into(),
        vec!["bash".into(), "-c".into(), script],
        Vec::new(),
    )
    .expect("valid restart-cancel command");
    let request = runne_runtime_client::SubmitTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-restart-cancel-{}", uuid::Uuid::now_v7()),
        )
        .unwrap(),
        conversation_id,
        workspace_id,
        "Run the explicitly approved restart-cancel fixture",
    )
    .unwrap()
    .with_local_command(command)
    .unwrap();
    let task_id = client
        .submit_task_run(request)
        .await
        .expect("submit restart-cancel command")
        .task_run_id();
    let approval_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let approval = loop {
        if let Some(row) = client
            .list_pending_approvals()
            .await
            .expect("read local approval")
            .into_iter()
            .find(|row| row.task_run_id() == task_id)
        {
            break row;
        }
        assert!(tokio::time::Instant::now() < approval_deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let approve = runne_runtime_client::ApprovalDecisionRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-restart-cancel-approve-{}", uuid::Uuid::now_v7()),
        )
        .unwrap(),
        approval.approval_id(),
        approval.request_version(),
        runne_runtime_client::ApprovalDecisionDto::Approve,
        *approval.action_digest(),
        approval.policy_revision(),
        1,
    )
    .unwrap();
    client
        .decide_approval(approve)
        .await
        .expect("approve exact restart-cancel command");

    let running_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let running = loop {
        let snapshot = client.get_task_run(task_id).await.unwrap();
        if snapshot.state() == runne_runtime_client::TaskRunState::Running
            && std::fs::read_to_string(&output)
                .is_ok_and(|text| text.contains("leader_started") && text.contains("child_started"))
        {
            break snapshot;
        }
        assert!(tokio::time::Instant::now() < running_deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let heartbeat_before = std::fs::metadata(&heartbeat)
        .expect("detached child heartbeat before reconnect")
        .len();
    let history_before_disconnect = receipt::read_taskrun_history(&client, task_id).await;
    drop(client);
    let disconnect_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::fs::metadata(&heartbeat)
            .expect("worker continues while no authenticated client is connected")
            .len()
            > heartbeat_before
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < disconnect_deadline,
            "local worker heartbeat did not advance while disconnected"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let profile = supervisor
        .renew_profile()
        .expect("rotate protected session while the local command runs");
    let reconnected = profile
        .connect(Duration::from_secs(10))
        .await
        .expect("reconnect authenticated client during local command");
    supervisor
        .record_client_ready(&reconnected)
        .expect("record client reconnection readiness");
    let reconnected_snapshot = reconnected
        .get_task_run(task_id)
        .await
        .expect("reconnect to the same local TaskRun");
    assert_eq!(
        reconnected_snapshot.state(),
        runne_runtime_client::TaskRunState::Running
    );
    assert_eq!(
        reconnected_snapshot.stream_version(),
        running.stream_version()
    );
    receipt::assert_replayed_taskrun_history(&reconnected, task_id, &history_before_disconnect)
        .await;
    eprintln!("RUN: client disconnect/reconnect observes same local TaskRun history");
    let cancel = runne_runtime_client::CancelTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-restart-cancel-request-{}", uuid::Uuid::now_v7()),
        )
        .unwrap(),
        task_id,
        running.stream_version(),
    );
    let cancel_ack = reconnected
        .cancel_task_run(cancel.clone())
        .await
        .expect("commit cancellation before daemon crash");
    let history_before_restart = receipt::read_taskrun_history(&reconnected, task_id).await;
    assert_eq!(
        reconnected.get_task_run(task_id).await.unwrap().state(),
        runne_runtime_client::TaskRunState::Cancelling,
        "cancellation is durable before the supervised daemon is killed"
    );
    let task_bytes = uuid::Uuid::parse_str(&task_id.to_string())
        .unwrap()
        .into_bytes();
    let connection = rusqlite::Connection::open(database).expect("inspect active cancellation");
    let (attempt_state, area_bytes): (String, Vec<u8>) = connection
        .query_row(
            "SELECT state,managed_area_identity FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("persisted command area before restart");
    assert!(
        matches!(attempt_state.as_str(), "running" | "cancel_requested"),
        "restart begins before local terminal settlement"
    );
    let identity =
        runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(&area_bytes).unwrap();
    let identity_bytes = identity.to_bytes();
    let binding = runne_platform::process_managed_area::ManagedAreaBinding::new(
        task_bytes,
        identity_bytes[68..84].try_into().unwrap(),
        identity_bytes[84..100].try_into().unwrap(),
    )
    .unwrap();
    let area_root =
        runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup().unwrap();
    let area = area_root.reopen_area(identity, binding).unwrap();
    assert!(
        area.is_populated().unwrap(),
        "detached TERM-ignore child is alive"
    );
    let receipt_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        receipt_count, 0,
        "no terminal receipt precedes daemon crash"
    );
    let daemon = supervisor.test_owned_child_id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(daemon, libc::SIGKILL) }, 0);
    supervisor
        .test_wait_for_exit(Duration::from_secs(10))
        .expect("reap daemon during local cancellation");
    let (state_after_reap, receipt_count_after_reap): (String, i64) = connection
        .query_row(
            "SELECT attempt.state,
                    (SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts receipt
                     WHERE receipt.taskrun_id=attempt.taskrun_id)
             FROM taskrun_local_command_attempts attempt WHERE attempt.taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("inspect crash window before replacement daemon starts");
    assert!(matches!(
        state_after_reap.as_str(),
        "running" | "cancel_requested"
    ));
    assert_eq!(
        receipt_count_after_reap, 0,
        "restart starts before stop receipt"
    );
    if remove_area_before_restart {
        missing_area::remove_owned_area(area, &heartbeat).await;
    }

    let bus = super::t1_support::fixture_session_bus(
        runtime_root.parent().expect("runtime parent"),
        "local-cancel-restart-bus-2.sock",
    );
    let spec = runne_platform_desktop::ProtectedBundledRuntimeLaunchSpec::new(
        executable.path(),
        runtime_root,
    )
    .expect("restarted cancellation launch spec")
    .with_openai_provider_activation()
    .with_validated_session_bus_address(&bus)
    .expect("restarted session bus");
    let mut restarted = runne_platform_desktop::ProtectedBundledRuntimeSupervisor::new(
        runne_platform_desktop::DevelopmentBundledRuntimeLauncher::new(),
        spec,
    );
    if let Err(error) = restarted.start() {
        let startup_diagnostic = missing_area::startup_diagnostic(runtime_root);
        panic!("restart same protected daemon: {error}; startup_diagnostic={startup_diagnostic}");
    }
    let recovered = restarted
        .take_runtime_profile()
        .expect("restarted profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("connect restarted daemon");
    restarted
        .record_client_ready(&recovered)
        .expect("record restarted readiness");
    if remove_area_before_restart {
        missing_area::assert_unconfirmed_after_restart(missing_area::RestartObservation {
            client: &recovered,
            task_id,
            expected_stream_version: cancel_ack.stream_version(),
            history_before_restart: &history_before_restart,
            database,
            task_bytes: &task_bytes,
            output: &output,
            heartbeat: &heartbeat,
        })
        .await;
        eprintln!("PASS: missing exact cgroup stays Cancelling with stop unconfirmed");
        return (recovered, restarted);
    }
    receipt::assert_restarted_cancel_finishes(
        &recovered,
        task_id,
        cancel,
        cancel_ack.stream_version(),
        &output,
        database,
    )
    .await;
    (recovered, restarted)
}
