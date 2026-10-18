use super::t1_taskrun_support::LocalTaskRunContext;
use std::time::Duration;

pub(super) async fn exercise(context: &mut LocalTaskRunContext<'_>) -> bool {
    let variant = std::env::var("RUNNE_TEST_T1_LOCAL_TERMINAL_VARIANT").unwrap_or_default();
    assert!(matches!(variant.as_str(), "success" | "failure" | "cancel"));
    eprintln!("RUN: protected local durable-terminal restart ({variant})");
    let marker = context
        .project_directory
        .join(format!("after-terminal-{variant}-marker"));
    std::fs::write(&marker, "").expect("create terminal marker");
    let script = match variant.as_str() {
        "success" => "printf success >> marker; exit 0",
        "failure" => "printf failure >> marker; exit 7",
        _ => "printf cancel >> marker; while true; do sleep 0.1; done",
    };
    let task_id = super::t1_local_barrier::submit_and_approve(context, &marker, script).await;
    let cancel = if variant == "cancel" {
        wait_for_marker(&marker, "cancel").await;
        let running = super::t1_local_barrier::wait_for_state(
            context,
            task_id,
            runne_runtime_client::TaskRunState::Running,
        )
        .await;
        let request = super::t1_local_barrier::cancel_request(
            task_id,
            running.stream_version(),
            "after-terminal-cancel",
        );
        let ack = context
            .client
            .cancel_task_run(request.clone())
            .await
            .expect("durable cancellation accepted before terminal settlement");
        Some((request, ack.stream_version()))
    } else {
        None
    };
    super::t1_local_barrier::wait_for_barrier("after-terminal");

    let task_bytes = uuid::Uuid::parse_str(&task_id.to_string())
        .unwrap()
        .into_bytes();
    let connection =
        rusqlite::Connection::open(context.database).expect("inspect durable terminal");
    let (attempt_state, exit, area_bytes): (String, Option<i32>, Vec<u8>) = connection
        .query_row(
            "SELECT state,exit_code,managed_area_identity FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("local terminal attempt row");
    let expected_attempt = if variant == "cancel" {
        "cancelled"
    } else {
        "completed"
    };
    // V68 keeps the observed flat leader code for live cancellations: the
    // stop terminates the managed area (SIGKILL leader => 128+9), and the
    // terminal sidecar retains the exact signal facts. Only recovery-owned
    // cancellations after a crash keep exit_code NULL (nothing is invented).
    let expected_exit = match variant.as_str() {
        "success" => Some(0),
        "failure" => Some(7),
        _ => Some(137),
    };
    assert_eq!(attempt_state, expected_attempt);
    assert_eq!(exit, expected_exit);
    let (receipt_count, released, terminal_event, release_event): (i64, String, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1),
                    occupation.state,receipt.terminal_event_id,occupation.release_event_id
             FROM taskrun_assignment_occupations occupation
             JOIN taskrun_terminal_settlement_receipts receipt USING(taskrun_id,fence)
             WHERE occupation.taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("durable terminal receipt and released occupation");
    assert_eq!(receipt_count, 1);
    assert_eq!(released, "released");
    assert_eq!(terminal_event, release_event);
    let before_restart = context.client.get_task_run(task_id).await.unwrap();
    let expected_state = match variant.as_str() {
        "success" | "failure" => runne_runtime_client::TaskRunState::Succeeded,
        _ => runne_runtime_client::TaskRunState::Cancelled,
    };
    assert_eq!(before_restart.state(), expected_state);
    if variant == "failure" {
        assert!(matches!(
            before_restart.terminal_result(),
            Some(runne_runtime_client::TaskRunTerminalResult::Failure { reason })
                if reason == "local_command_exit_7"
        ));
    }
    let expected_terminal_result = before_restart.terminal_result().cloned();
    let scope = runne_runtime_client::ReplayScope::new(
        runne_runtime_client::ReplayAggregateKind::TaskRun,
        task_id,
    );
    let mut history_before_restart = Vec::new();
    let _history = context
        .client
        .catch_up(scope, None, |delivery| {
            let event = delivery.event();
            history_before_restart.push((
                delivery.event_id(),
                event.sequence(),
                *delivery.canonical_digest(),
                event.event_type().to_owned(),
            ));
            Ok::<_, ()>(())
        })
        .await
        .expect("capture complete TaskRun history before restart");

    let area_identity =
        runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(&area_bytes).unwrap();
    let identity_bytes = area_identity.to_bytes();
    let binding = runne_platform::process_managed_area::ManagedAreaBinding::new(
        task_bytes,
        identity_bytes[68..84].try_into().unwrap(),
        identity_bytes[84..100].try_into().unwrap(),
    )
    .unwrap();
    let root = runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup()
        .expect("current delegated cgroup root");
    let area = root.reopen_area(area_identity.clone(), binding).unwrap();
    assert!(
        !area.is_populated().unwrap(),
        "terminal receipt follows confirmed empty cgroup"
    );

    let daemon = context.supervisor.test_owned_child_id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(daemon, libc::SIGKILL) }, 0);
    context
        .supervisor
        .test_wait_for_exit(Duration::from_secs(10))
        .expect("reap daemon after terminal receipt, before area drop");
    drop(connection);

    let bus = super::t1_support::fixture_session_bus(
        context.runtime_root.parent().expect("runtime parent"),
        &format!("after-terminal-{variant}-bus.sock"),
    );
    let spec = runne_platform_desktop::ProtectedBundledRuntimeLaunchSpec::new(
        context.executable.path(),
        context.runtime_root,
    )
    .expect("terminal-restart launch spec")
    .with_openai_provider_activation()
    .with_validated_session_bus_address(&bus)
    .expect("terminal-restart session bus");
    let mut restarted = runne_platform_desktop::ProtectedBundledRuntimeSupervisor::new(
        runne_platform_desktop::DevelopmentBundledRuntimeLauncher::new(),
        spec,
    );
    restarted
        .start()
        .expect("restart same protected daemon root");
    let recovered = restarted
        .take_runtime_profile()
        .expect("restarted runtime profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("connect restarted daemon");
    restarted
        .record_client_ready(&recovered)
        .expect("record restarted readiness");
    let after_restart = recovered.get_task_run(task_id).await.unwrap();
    assert_eq!(after_restart.state(), expected_state);
    assert_eq!(
        after_restart.terminal_result(),
        expected_terminal_result.as_ref()
    );
    assert_eq!(
        after_restart.stream_version(),
        before_restart.stream_version()
    );
    let mut replayed = Vec::new();
    let mut history_after_restart = Vec::new();
    let _history = recovered
        .catch_up(scope, None, |delivery| {
            let event = delivery.event();
            history_after_restart.push((
                delivery.event_id(),
                event.sequence(),
                *delivery.canonical_digest(),
                event.event_type().to_owned(),
            ));
            if let runne_runtime_client::CanonicalReplayPayload::TaskRun(payload) =
                delivery.event().payload()
            {
                replayed.push(payload.kind());
            }
            Ok::<_, ()>(())
        })
        .await
        .expect("replay stable TaskRun history after restart");
    assert_eq!(history_after_restart, history_before_restart);
    assert!(replayed.contains(&runne_runtime_client::TaskRunTimelineKind::Created));
    assert!(replayed.contains(&runne_runtime_client::TaskRunTimelineKind::AttemptStarted));
    let output = std::fs::read_to_string(&marker).unwrap();
    assert_eq!(
        output,
        match variant.as_str() {
            "success" => "success",
            "failure" => "failure",
            _ => "cancel",
        }
    );
    let count: i64 = rusqlite::Connection::open(context.database)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "restart does not add a second terminal receipt");
    assert!(
        !root.remove_area_if_present(area_identity).unwrap(),
        "restart already removed the exact empty managed area"
    );
    if let Some((cancel, ack_version)) = cancel {
        let replay = recovered.cancel_task_run(cancel).await.unwrap();
        assert_eq!(replay.stream_version(), ack_version);
    }
    drop(recovered);
    *context.supervisor = restarted;
    eprintln!(
        "PASS: durable local terminal and receipt survive daemon SIGKILL before cgroup cleanup"
    );
    true
}

async fn wait_for_marker(path: &std::path::Path, expected: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let actual = std::fs::read_to_string(path).expect("read local command start marker");
        if actual == expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "local command start marker did not reach {expected:?}; last content was {actual:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
