use super::t1_taskrun_support::LocalTaskRunContext;
use std::time::Duration;

#[path = "t1_local_barrier/cleanup.rs"]
mod cleanup;
#[path = "t1_local_lost_ack.rs"]
mod lost_ack;

pub(super) async fn exercise_if_requested(context: &mut LocalTaskRunContext<'_>) -> bool {
    match std::env::var("RUNNE_TEST_LOCAL_WORKER_BARRIER")
        .ok()
        .as_deref()
    {
        Some("pre-release") => cancel_before_release(context).await,
        Some("after-exit") => complete_exit_race(context).await,
        Some("after-terminal") => {
            if std::env::var_os("RUNNE_TEST_T1_LOCAL_LOST_ACK").as_deref()
                == Some(std::ffi::OsStr::new("1"))
            {
                lost_ack::exercise(context).await
            } else {
                super::t1_local_terminal_restart::exercise(context).await
            }
        }
        _ => false,
    }
}

async fn cancel_before_release(context: &LocalTaskRunContext<'_>) -> bool {
    eprintln!("RUN: protected local cancellation before gated release");
    let marker = context.project_directory.join("barrier-pre-release-marker");
    std::fs::write(&marker, "").expect("create absent user-code marker");
    let task_id = submit_and_approve(context, &marker, "exit 0").await;
    wait_for_barrier("pre-release");
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "");
    let before = context.client.get_task_run(task_id).await.unwrap();
    assert_eq!(before.state(), runne_runtime_client::TaskRunState::Running);
    let cancel = cancel_request(task_id, before.stream_version(), "pre-release");
    context
        .client
        .cancel_task_run(cancel)
        .await
        .expect("public cancellation commits before GO");
    release_barrier("pre-release");
    let terminal = wait_for_state(
        context,
        task_id,
        runne_runtime_client::TaskRunState::Cancelled,
    )
    .await;
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "");
    cleanup::assert_local_settled(context, task_id, "cancelled", None);
    assert_eq!(
        terminal.state(),
        runne_runtime_client::TaskRunState::Cancelled
    );
    eprintln!("PASS: public cancellation fenced gated release and user code never ran");
    true
}

async fn complete_exit_race(context: &LocalTaskRunContext<'_>) -> bool {
    let race = std::env::var("RUNNE_TEST_T1_LOCAL_BARRIER_RACE").unwrap_or_default();
    let cancel_wins = match race.as_str() {
        "cancel-before-terminal" => true,
        "complete-before-cancel" => false,
        _ => panic!("closed protected local race mode required"),
    };
    eprintln!("RUN: protected local exit-proof completion/cancellation ordering");
    let marker = context.project_directory.join("barrier-after-exit-marker");
    std::fs::write(&marker, "").expect("create exit marker");
    let task_id = submit_and_approve(context, &marker, "printf finished >> marker; exit 0").await;
    wait_for_barrier("after-exit");
    let row = attempt(context.database, task_id);
    assert_eq!(
        row.0, "completed",
        "factual local exit is durable before workflow terminal"
    );
    assert_eq!(row.1, Some(0));
    let running = context.client.get_task_run(task_id).await.unwrap();
    assert_eq!(running.state(), runne_runtime_client::TaskRunState::Running);
    if cancel_wins {
        context
            .client
            .cancel_task_run(cancel_request(
                task_id,
                running.stream_version(),
                "exit-proof-cancel",
            ))
            .await
            .expect("public cancel wins before workflow completion");
    }
    release_barrier("after-exit");
    let expected = if cancel_wins {
        runne_runtime_client::TaskRunState::Cancelled
    } else {
        runne_runtime_client::TaskRunState::Succeeded
    };
    let terminal = wait_for_state(context, task_id, expected).await;
    if !cancel_wins {
        let late_cancel = cancel_request(task_id, terminal.stream_version(), "after-complete");
        assert!(
            context.client.cancel_task_run(late_cancel).await.is_err(),
            "committed workflow completion rejects a later cancel"
        );
    }
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "finished");
    cleanup::assert_local_settled(context, task_id, "completed", Some(0));
    assert_eq!(terminal.state(), expected);
    eprintln!("PASS: local factual exit and workflow cancellation/completion remain distinct");
    true
}

pub(super) async fn submit_and_approve(
    context: &LocalTaskRunContext<'_>,
    marker: &std::path::Path,
    script: &str,
) -> runne_runtime_client::CanonicalId {
    let command_script = script.replace("marker", &marker.display().to_string());
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
        ".".into(),
        vec!["bash".into(), "-c".into(), command_script],
        Vec::new(),
    )
    .unwrap();
    let identity = runne_runtime_client::CommandIdentity::new(
        runne_runtime_client::CanonicalId::now_v7(),
        format!("t1-local-barrier-{}", uuid::Uuid::now_v7()),
    )
    .unwrap();
    let request = runne_runtime_client::SubmitTaskRunRequest::new(
        identity,
        context.conversation_id,
        context.workspace_id,
        "Run the explicitly approved local barrier fixture",
    )
    .unwrap()
    .with_local_command(command)
    .unwrap();
    let task_id = context
        .client
        .submit_task_run(request)
        .await
        .unwrap()
        .task_run_id();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let approval = loop {
        if let Some(row) = context
            .client
            .list_pending_approvals()
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.task_run_id() == task_id)
        {
            break row;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "approval timeout; local_preapproval_stage={}",
            super::t1_startup_diagnostic::local_preapproval_diagnostic(context.runtime_root)
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    context
        .client
        .decide_approval(
            runne_runtime_client::ApprovalDecisionRequest::new(
                runne_runtime_client::CommandIdentity::new(
                    runne_runtime_client::CanonicalId::now_v7(),
                    format!("t1-local-barrier-approve-{}", uuid::Uuid::now_v7()),
                )
                .unwrap(),
                approval.approval_id(),
                approval.request_version(),
                runne_runtime_client::ApprovalDecisionDto::Approve,
                *approval.action_digest(),
                approval.policy_revision(),
                1,
            )
            .unwrap(),
        )
        .await
        .expect("approve exact local command");
    task_id
}

pub(super) fn cancel_request(
    task_id: runne_runtime_client::CanonicalId,
    version: u64,
    suffix: &str,
) -> runne_runtime_client::CancelTaskRunRequest {
    runne_runtime_client::CancelTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-local-barrier-cancel-{suffix}-{}", uuid::Uuid::now_v7()),
        )
        .unwrap(),
        task_id,
        version,
    )
}

pub(super) async fn wait_for_state(
    context: &LocalTaskRunContext<'_>,
    task_id: runne_runtime_client::CanonicalId,
    state: runne_runtime_client::TaskRunState,
) -> runne_runtime_client::TaskRunSnapshot {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let snapshot = context.client.get_task_run(task_id).await.unwrap();
        if snapshot.state() == state {
            return snapshot;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "TaskRun terminal timeout"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

pub(super) fn wait_for_barrier(stage: &str) {
    let directory = std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR").unwrap();
    let entered = std::path::PathBuf::from(&directory).join(format!("{stage}.entered"));
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !entered.is_file() {
        assert!(
            std::time::Instant::now() < deadline,
            "worker barrier timeout"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn release_barrier(stage: &str) {
    let directory = std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR").unwrap();
    std::fs::write(
        std::path::PathBuf::from(directory).join(format!("{stage}.release")),
        b"continue",
    )
    .expect("release protected worker barrier");
}

pub(super) fn attempt(
    database: &std::path::Path,
    task_id: runne_runtime_client::CanonicalId,
) -> (String, Option<i32>) {
    let bytes = uuid::Uuid::parse_str(&task_id.to_string())
        .unwrap()
        .into_bytes();
    rusqlite::Connection::open(database)
        .unwrap()
        .query_row(
            "SELECT state,exit_code FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}
