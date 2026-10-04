use super::*;
#[path = "t1_local_commands/rejected_review.rs"]
mod rejected_review;

pub(super) async fn exercise_local_commands(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &std::path::Path,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) {
    let current_client = client.clone();
    for (name, exit_code) in [("success", 0), ("failure", 7)] {
        eprintln!("RUN: protected typed local-command {name} TaskRun");
        let marker = format!("local-command-{name}-{}", uuid::Uuid::now_v7());
        let marker_path = project_directory.join(format!("{name}-marker"));
        let started_path = project_directory.join(format!("{name}-started"));
        let heartbeat_path = project_directory.join(format!("{name}-heartbeat"));
        let release_path = project_directory.join(format!("{name}-release"));
        std::fs::write(&marker_path, "").expect("prepare an existing workspace file");
        let _ = std::fs::remove_file(&started_path);
        let _ = std::fs::remove_file(&heartbeat_path);
        let _ = std::fs::remove_file(&release_path);
        let prompt = format!("Run the explicitly approved {name} fixture command");
        let script = if exit_code == 0 {
            format!(
                "touch '{}'; while [ ! -e '{}' ]; do printf h >> '{}'; sleep 0.02; done; printf '%s\\n' '{}' >> '{}'; exit 0",
                started_path.display(),
                release_path.display(),
                heartbeat_path.display(),
                marker,
                marker_path.display()
            )
        } else {
            format!(
                "printf '%s\\n' '{}' >> '{}' || exit 18; exit {exit_code}",
                marker,
                marker_path.display()
            )
        };
        let command = runne_api::TaskRunLocalCommand::new(
            runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
            ".".into(),
            vec!["bash".into(), "-c".into(), script],
            Vec::new(),
        )
        .expect("valid structured shell command");
        let identity = runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-local-{name}-{}", uuid::Uuid::now_v7()),
        )
        .expect("local command identity");
        let request = runne_runtime_client::SubmitTaskRunRequest::new(
            identity,
            conversation_id,
            workspace_id,
            prompt,
        )
        .expect("valid local command description")
        .with_local_command(command)
        .expect("select structured local command");
        let submitted = current_client
            .submit_task_run(request)
            .await
            .expect("submit typed local command");
        let task_run_id = submitted.task_run_id();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let approval = loop {
            if let Some(approval) = current_client
                .list_pending_approvals()
                .await
                .expect("read public pending approvals")
                .into_iter()
                .find(|approval| approval.task_run_id() == task_run_id)
            {
                break approval;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "local approval was not created: task={:?}, row={:?}, pending={:?}, local_preapproval_stage={}",
                current_client
                    .get_task_run(task_run_id)
                    .await
                    .map(|snapshot| snapshot.state()),
                local_attempt_row(database, task_run_id),
                current_client
                    .list_pending_approvals()
                    .await
                    .map(|rows| rows.len()),
                super::t1_startup_diagnostic::local_preapproval_diagnostic(runtime_root)
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(approval.action(), "local_command.execute");
        let review: serde_json::Value = serde_json::from_str(approval.risk_summary())
            .expect("reviewable structured command summary");
        assert_eq!(review["kind"], "structured_local_command");
        assert_eq!(review["executable"]["system_catalog_id"], "shell");
        assert_eq!(review["cwd"], ".");
        assert_eq!(review["argv"][0], "bash");
        assert!(review["argv"][2].as_str().unwrap().contains(&marker));
        assert_eq!(review["environment_values_are_redacted"], true);

        let decision = runne_runtime_client::ApprovalDecisionRequest::new(
            runne_runtime_client::CommandIdentity::new(
                runne_runtime_client::CanonicalId::now_v7(),
                format!("t1-local-approve-{}", uuid::Uuid::now_v7()),
            )
            .expect("approval decision identity"),
            approval.approval_id(),
            approval.request_version(),
            runne_runtime_client::ApprovalDecisionDto::Approve,
            *approval.action_digest(),
            approval.policy_revision(),
            1,
        )
        .expect("exact approval decision");
        let decision = current_client
            .decide_approval(decision)
            .await
            .expect("approve exact local command");
        assert_eq!(
            decision.state(),
            runne_runtime_client::ApprovalStateDto::Approved
        );
        assert_eq!(
            current_client
                .get_approval(approval.approval_id())
                .await
                .expect("read approved command review")
                .state(),
            runne_runtime_client::ApprovalStateDto::Approved
        );

        if exit_code == 0 {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            while !started_path.exists() {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "local command did not start"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        if exit_code == 0 {
            std::fs::write(&release_path, "release").expect("release approved worker");
        }

        let task_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let snapshot = loop {
            let snapshot = current_client
                .get_task_run(task_run_id)
                .await
                .expect("read local TaskRun");
            if matches!(
                snapshot.state(),
                runne_runtime_client::TaskRunState::Succeeded
                    | runne_runtime_client::TaskRunState::Failed
            ) {
                break snapshot;
            }
            assert!(
                tokio::time::Instant::now() < task_deadline,
                "local command did not settle: state {:?}, database {:?}, marker exists {}",
                snapshot.state(),
                local_attempt_row(database, task_run_id),
                marker_path.exists()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        if exit_code == 0 {
            assert_eq!(
                snapshot.state(),
                runne_runtime_client::TaskRunState::Succeeded
            );
            assert!(matches!(
                snapshot.terminal_result(),
                Some(runne_runtime_client::TaskRunTerminalResult::Success)
            ));
        } else {
            assert_eq!(
                snapshot.state(),
                runne_runtime_client::TaskRunState::Succeeded
            );
            assert!(matches!(
                snapshot.terminal_result(),
                Some(runne_runtime_client::TaskRunTerminalResult::Failure { reason })
                    if reason == "local_command_exit_7"
            ));
            let effects = current_client
                .get_task_run_effects(task_run_id)
                .await
                .expect("read typed local exit facts from the public effects endpoint");
            assert_eq!(effects.stream_version(), snapshot.stream_version());
            let local = effects
                .local_command()
                .expect("the completed local TaskRun retains its process outcome");
            assert_eq!(
                local.outcome(),
                runne_runtime_client::LocalExecutionOutcome::Exited
            );
            assert_eq!(local.exit_code(), Some(7));
            assert_eq!(
                effects.remote().outcome(),
                runne_runtime_client::RemoteEffectOutcome::NotApplicable
            );
        }
        let markers = std::fs::read_to_string(&marker_path).unwrap_or_else(|error| {
            panic!(
                "command wrote workspace marker: {error}; task state {:?}; local row {:?}",
                snapshot.state(),
                local_attempt_row(database, task_run_id)
            );
        });
        assert_eq!(markers.lines().filter(|line| *line == marker).count(), 1);
        if exit_code == 0 {
            let fresh_cancel = runne_runtime_client::CancelTaskRunRequest::new(
                runne_runtime_client::CommandIdentity::new(
                    runne_runtime_client::CanonicalId::now_v7(),
                    format!("t1-local-cancel-after-complete-{}", uuid::Uuid::now_v7()),
                )
                .unwrap(),
                task_run_id,
                snapshot.stream_version(),
            );
            assert!(
                current_client.cancel_task_run(fresh_cancel).await.is_err(),
                "a fresh cancel after terminal completion cannot rewrite the winning result"
            );
            let replayed = current_client
                .get_task_run(task_run_id)
                .await
                .expect("reread completed local TaskRun history");
            assert_eq!(replayed.state(), snapshot.state());
            assert_eq!(replayed.terminal_result(), snapshot.terminal_result());
        }
        eprintln!("PASS: protected typed local-command {name} TaskRun");
    }
    rejected_review::exercise(
        &current_client,
        conversation_id,
        workspace_id,
        project_directory,
        database,
    )
    .await;
}

fn local_attempt_row(
    database: &std::path::Path,
    task_run_id: runne_runtime_client::CanonicalId,
) -> Option<(String, Option<i64>, i64)> {
    let connection = rusqlite::Connection::open(database).ok()?;
    let id_bytes = uuid::Uuid::parse_str(&task_run_id.to_string())
        .ok()?
        .into_bytes();
    connection
        .query_row(
            "SELECT state, exit_code, (SELECT COUNT(*) FROM taskrun_assignments WHERE taskrun_id=?1) FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [id_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .ok()
}
