use super::*;

pub(super) async fn exercise_daemon_crash_recovery(
    context: &mut super::t1_taskrun_support::LocalTaskRunContext<'_>,
) {
    let client = &context.client;
    let conversation_id = context.conversation_id;
    let workspace_id = context.workspace_id;
    let project_directory = context.project_directory;
    let database = context.database;
    let runtime_root = context.runtime_root;
    let executable = context.executable;
    let supervisor = &mut *context.supervisor;
    eprintln!("RUN: protected local-command daemon crash and restart recovery");
    let marker = project_directory.join("crash-execution-count");
    let leader = project_directory.join("crash-leader-started");
    let detached = project_directory.join("crash-detached-started");
    for path in [&marker, &leader, &detached] {
        std::fs::write(path, "").expect("prepare restart fixture marker");
    }
    let script = format!(
        "printf 'run\\n' >> '{}'; setsid bash -c 'trap \"\" TERM; printf child > \"{}\"; while true; do sleep 0.1; done' & child=$!; printf leader > '{}'; wait \"$child\"",
        marker.display(),
        detached.display(),
        leader.display()
    );
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
        ".".into(),
        vec!["bash".into(), "-c".into(), script],
        Vec::new(),
    )
    .expect("valid structured restart command");
    let identity = runne_runtime_client::CommandIdentity::new(
        runne_runtime_client::CanonicalId::now_v7(),
        format!("t1-local-crash-{}", uuid::Uuid::now_v7()),
    )
    .expect("restart fixture submit identity");
    let submitted = client
        .submit_task_run(
            runne_runtime_client::SubmitTaskRunRequest::new(
                identity,
                conversation_id,
                workspace_id,
                "Run the explicitly approved restart recovery fixture",
            )
            .expect("restart command description")
            .with_local_command(command)
            .expect("typed local restart command"),
        )
        .await
        .expect("submit restart command");
    let task_run_id = submitted.task_run_id();
    let approval_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let approval = loop {
        if let Some(approval) = client
            .list_pending_approvals()
            .await
            .expect("list restart approval")
            .into_iter()
            .find(|item| item.task_run_id() == task_run_id)
        {
            break approval;
        }
        assert!(tokio::time::Instant::now() < approval_deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let approval_command = runne_runtime_client::ApprovalDecisionRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-local-crash-approve-{}", uuid::Uuid::now_v7()),
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
        .decide_approval(approval_command)
        .await
        .expect("approve exact restart command");
    wait_for_file(&leader).await;
    wait_for_file(&detached).await;
    let run_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .get_task_run(task_run_id)
            .await
            .expect("read running restart fixture")
            .state()
            == runne_runtime_client::TaskRunState::Running
        {
            break;
        }
        assert!(tokio::time::Instant::now() < run_deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "run\n");
    let pid = supervisor.test_owned_child_id() as libc::pid_t;
    let killed = unsafe { libc::kill(pid, libc::SIGKILL) };
    assert_eq!(killed, 0, "SIGKILL only the exact supervised daemon");
    supervisor
        .test_wait_for_exit(Duration::from_secs(10))
        .expect("reap killed supervised daemon");
    let task_bytes = uuid::Uuid::parse_str(&task_run_id.to_string())
        .expect("TaskRun identifier")
        .into_bytes();

    let socket = super::t1_support::fixture_session_bus(
        runtime_root.parent().expect("temporary runtime parent"),
        "local-command-restart-bus.sock",
    );
    let spec = runne_platform_desktop::ProtectedBundledRuntimeLaunchSpec::new(
        executable.path(),
        runtime_root,
    )
    .expect("restart launch spec")
    .with_openai_provider_activation()
    .with_validated_session_bus_address(&socket)
    .expect("restart fixture session bus");
    let mut restarted = runne_platform_desktop::ProtectedBundledRuntimeSupervisor::new(
        runne_platform_desktop::DevelopmentBundledRuntimeLauncher::new(),
        spec,
    );
    if let Err(error) = restarted.start() {
        let status: Option<(String, i64)> =
            rusqlite::Connection::open(database)
                .ok()
                .and_then(|connection| {
                    connection
                        .query_row(
                            "SELECT attempt.state,stream.current_version
                         FROM taskrun_local_command_attempts attempt
                         JOIN aggregate_streams stream ON stream.aggregate_type=1
                           AND stream.aggregate_id=attempt.taskrun_id
                         WHERE attempt.taskrun_id=?1",
                            [task_bytes.as_slice()],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .ok()
                });
        panic!("restart same protected runtime root: {error}; local_attempt={status:?}");
    }
    let restarted_client = restarted
        .take_runtime_profile()
        .expect("restarted runtime profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("connect restarted daemon");
    restarted
        .record_client_ready(&restarted_client)
        .expect("record restarted profile readiness");
    let outcome_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let snapshot = restarted_client
            .get_task_run(task_run_id)
            .await
            .expect("read recovered same TaskRun ID");
        if snapshot.state() == runne_runtime_client::TaskRunState::Unrecoverable {
            break;
        }
        assert!(
            tokio::time::Instant::now() < outcome_deadline,
            "restart did not reconcile old effect: {:?}",
            snapshot.state()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "run\n",
        "recovery observes and stops the old cgroup without relaunching"
    );
    assert!(
        std::fs::read_to_string(&detached).is_ok(),
        "the detached child entered the pre-crash body"
    );
    let connection = rusqlite::Connection::open(database).expect("open recovered event log");
    let (bytes, attempt_state, exit_code): (Vec<u8>, String, Option<i32>) = connection
        .query_row(
            "SELECT managed_area_identity,state,exit_code FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("recovered attempt area identity");
    assert_eq!(attempt_state, "outcome_unknown");
    assert_eq!(exit_code, None, "restart records no invented process exit");
    let durable_stop_proof: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM taskrun_local_command_attempts a
             JOIN taskrun_local_command_stop_receipts s
               ON s.taskrun_id=a.taskrun_id AND s.attempt_id=a.attempt_id AND s.fence=a.fence
             JOIN taskrun_terminal_settlement_receipts t
               ON t.taskrun_id=s.taskrun_id AND t.fence=s.fence
                  AND t.attempt_id=s.attempt_id AND t.node_id=s.historic_node_id
                  AND t.node_epoch=s.historic_node_epoch
                  AND t.terminal_event_id=s.terminal_event_id
                  AND t.terminal_version=s.terminal_version
             JOIN taskrun_assignment_occupations o
               ON o.taskrun_id=s.taskrun_id AND o.fence=s.fence
             JOIN events terminal ON terminal.event_id=s.terminal_event_id
               AND terminal.aggregate_id=s.taskrun_id AND terminal.sequence=s.terminal_version
             WHERE a.taskrun_id=?1 AND a.state='outcome_unknown' AND a.exit_code IS NULL
               AND s.stop_kind='outcome_unknown' AND s.proof_node_id=s.historic_node_id
               AND s.proof_node_epoch>a.node_epoch
               AND s.managed_area_identity=a.managed_area_identity
               AND s.command_digest=a.command_digest
               AND o.state='released' AND o.release_event_id=s.terminal_event_id
               AND terminal.causation_id IS NOT NULL",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .expect("read recovered native stop proof");
    assert_eq!(
        durable_stop_proof, 1,
        "exact unknown-stop and released receipts persist"
    );
    let identity = runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(&bytes)
        .expect("persisted managed area identity");
    let identity_bytes = identity.to_bytes();
    let binding = runne_platform::process_managed_area::ManagedAreaBinding::new(
        task_bytes,
        identity_bytes[68..84].try_into().unwrap(),
        identity_bytes[84..100].try_into().unwrap(),
    )
    .expect("persisted attempt binding");
    let root = runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup()
        .expect("delegated recovery root");
    assert!(
        root.reopen_area(identity, binding).is_err(),
        "recovery cleaned the exact empty area"
    );
    restarted.stop().expect("stop restarted protected daemon");
    eprintln!("PASS: protected local-command daemon crash and restart recovery");
}

async fn wait_for_file(path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "fixture marker did not appear"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
