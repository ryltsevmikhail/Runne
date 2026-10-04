use super::*;

pub(super) async fn exercise_running_cancel(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &std::path::Path,
    database: &std::path::Path,
) {
    eprintln!("RUN: protected typed local-command cancellation and repeated cancel");
    let marker_path = project_directory.join("cancel-marker");
    std::fs::write(&marker_path, "").expect("prepare cancellation marker file");
    let marker = marker_path.display().to_string();
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
        ".".into(),
        vec![
            "bash".into(),
            "-c".into(),
            format!(
                "printf 'started\\n' > '{marker}' || exit 18; setsid bash -c 'trap \"\" TERM; echo descendant_started >> \"{marker}\"; sleep 5; echo descendant_late >> \"{marker}\"' & child=$!; while ! grep -q descendant_started '{marker}'; do sleep 0.02; done; wait \"$child\"; printf 'late\\n' >> '{marker}' || exit 19"
            ),
        ],
        Vec::new(),
    )
    .expect("valid cancellable structured command");
    let identity = runne_runtime_client::CommandIdentity::new(
        runne_runtime_client::CanonicalId::now_v7(),
        format!("t1-local-cancel-{}", uuid::Uuid::now_v7()),
    )
    .expect("local cancellation submit identity");
    let request = runne_runtime_client::SubmitTaskRunRequest::new(
        identity,
        conversation_id,
        workspace_id,
        "Run the explicitly approved cancellation fixture",
    )
    .expect("valid cancellation description")
    .with_local_command(command)
    .expect("select local cancellation command");
    let task_run_id = client
        .submit_task_run(request)
        .await
        .expect("submit cancellable local command")
        .task_run_id();
    let approval_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let approval = loop {
        if let Some(approval) = client
            .list_pending_approvals()
            .await
            .expect("list cancellation approval")
            .into_iter()
            .find(|approval| approval.task_run_id() == task_run_id)
        {
            break approval;
        }
        assert!(tokio::time::Instant::now() < approval_deadline);
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let decision = runne_runtime_client::ApprovalDecisionRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-local-cancel-approve-{}", uuid::Uuid::now_v7()),
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
        .decide_approval(decision)
        .await
        .expect("approve exact cancellation command");
    let running_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let running = loop {
        let snapshot = client.get_task_run(task_run_id).await.unwrap();
        if snapshot.state() == runne_runtime_client::TaskRunState::Running {
            break snapshot;
        }
        assert!(
            tokio::time::Instant::now() < running_deadline,
            "command failed to reach Running: {:?}",
            snapshot.state()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let body_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::fs::read_to_string(&marker_path).is_ok_and(|contents| {
            contents.starts_with("started") && contents.contains("descendant_started")
        }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < body_deadline,
            "leader and TERM-ignoring detached child did not enter the running body"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let cancel = runne_runtime_client::CancelTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-local-cancel-request-{}", uuid::Uuid::now_v7()),
        )
        .unwrap(),
        task_run_id,
        running.stream_version(),
    );
    let first = client
        .cancel_task_run(cancel.clone())
        .await
        .expect("durably request local cancellation");
    let replay = client
        .cancel_task_run(cancel)
        .await
        .expect("replay same cancellation request");
    assert_eq!(first.stream_version(), replay.stream_version());
    let fresh_cancel = runne_runtime_client::CancelTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-local-cancel-fresh-{}", uuid::Uuid::now_v7()),
        )
        .unwrap(),
        task_run_id,
        first.stream_version(),
    );
    assert!(
        client.cancel_task_run(fresh_cancel).await.is_err(),
        "a distinct cancel command cannot rewrite an already-cancelling run"
    );
    let terminal_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let snapshot = client.get_task_run(task_run_id).await.unwrap();
        if snapshot.state() == runne_runtime_client::TaskRunState::Cancelled {
            break;
        }
        assert!(
            tokio::time::Instant::now() < terminal_deadline,
            "cancellation did not settle: {:?}",
            (snapshot.state(), local_attempt_row(database, task_run_id))
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    std::thread::sleep(Duration::from_millis(150));
    let output = std::fs::read_to_string(&marker_path).expect("read cancellation marker");
    assert!(
        output.starts_with("started"),
        "command reached its running body"
    );
    assert!(
        output.contains("descendant_started"),
        "setsid descendant entered its TERM-ignoring body before cancellation"
    );
    assert!(
        !output.contains("late"),
        "no code ran after cancellation won"
    );
    let connection = rusqlite::Connection::open(database).expect("open TaskRun database");
    let task_id = uuid::Uuid::parse_str(&task_run_id.to_string())
        .expect("TaskRun identifier")
        .into_bytes();
    let (attempt_state, area_bytes): (String, Vec<u8>) = connection
        .query_row(
            "SELECT state,managed_area_identity FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [task_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("durable local stop proof");
    assert_eq!(attempt_state, "cancelled");
    let (occupation, release_event, receipt_event): (String, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT o.state,o.release_event_id,r.terminal_event_id
             FROM taskrun_assignment_occupations o
             JOIN taskrun_terminal_settlement_receipts r USING(taskrun_id,fence)
             WHERE o.taskrun_id=?1",
            [task_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("cancellation terminal receipt and released occupation");
    assert_eq!(occupation, "released");
    assert_eq!(release_event, receipt_event);
    let identity =
        runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(&area_bytes)
            .expect("persisted managed-area identity");
    let identity_bytes = identity.to_bytes();
    let binding = runne_platform::process_managed_area::ManagedAreaBinding::new(
        task_id,
        identity_bytes[68..84].try_into().unwrap(),
        identity_bytes[84..100].try_into().unwrap(),
    )
    .expect("persisted managed-area binding");
    let root = runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup()
        .expect("delegated cgroup root remains available");
    assert!(
        root.reopen_area(identity, binding).is_err(),
        "settled area was removed"
    );
    eprintln!("PASS: protected typed local-command cancellation and repeated cancel");
}

fn local_attempt_row(
    database: &std::path::Path,
    task_run_id: runne_runtime_client::CanonicalId,
) -> Option<(String, Option<i64>)> {
    let connection = rusqlite::Connection::open(database).ok()?;
    let id = uuid::Uuid::parse_str(&task_run_id.to_string())
        .ok()?
        .into_bytes();
    connection
        .query_row(
            "SELECT state,exit_code FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok()
}
