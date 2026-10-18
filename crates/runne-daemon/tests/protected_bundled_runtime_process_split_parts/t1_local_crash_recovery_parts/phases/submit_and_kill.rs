use std::path::{Path, PathBuf};
use std::time::Duration;

use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "The crash phase carries the exact client, supervisor, root, and expected mode handles."
)]
pub(super) async fn run(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    runtime_root: &Path,
    executable: &owner_private::ControlledExecutable,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    expected_permission_mode: Option<runne_api::PermissionModeV1>,
) -> (
    runne_api::PermissionModeStatusV1,
    runne_runtime_client::CanonicalId,
    [u8; 16],
    PathBuf,
    PathBuf,
    runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    runne_runtime_client::AuthenticatedRuntimeClient,
) {
    eprintln!("RUN: protected local-command daemon crash and restart recovery");
    let permission_before = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read selected permission mode before local crash");
    if let Some(expected) = expected_permission_mode {
        assert_eq!(permission_before.selected_mode, expected);
    }
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
    if permission_before.selected_mode == runne_api::PermissionModeV1::FullAccess {
        let run_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if client
                .get_task_run(task_run_id)
                .await
                .expect("read full-access restart fixture")
                .state()
                == runne_runtime_client::TaskRunState::Running
            {
                break;
            }
            assert!(tokio::time::Instant::now() < run_deadline);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            client
                .list_pending_approvals()
                .await
                .expect("list full-access restart approvals")
                .into_iter()
                .all(|item| item.task_run_id() != task_run_id)
        );
    } else {
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
    }
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
    let task_bytes = uuid::Uuid::parse_str(&task_run_id.to_string())
        .expect("TaskRun identifier")
        .into_bytes();
    let route_connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open pre-crash route read-only");
    let route: (i64, i64, i64) = route_connection
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes
             WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read committed pre-crash permission route");
    assert_eq!(route, (2, 3, 68));
    drop(route_connection);
    let pid = supervisor.test_owned_child_id() as libc::pid_t;
    let killed = unsafe { libc::kill(pid, libc::SIGKILL) };
    assert_eq!(killed, 0, "SIGKILL only the exact supervised daemon");
    assert_eq!(
        supervisor
            .test_wait_for_exit(Duration::from_secs(10))
            .expect("reap killed supervised daemon"),
        runne_platform_desktop::BundledRuntimeProcessStatus::Exited,
        "the exact SIGKILLed supervisor child exited"
    );
    supervisor.stop().expect("clear reaped supervisor handle");

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
        let status: Option<(String, i64)> = rusqlite::Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
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

    (
        permission_before,
        task_run_id,
        task_bytes,
        marker,
        detached,
        restarted,
        restarted_client,
    )
}
