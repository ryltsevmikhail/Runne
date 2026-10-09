use std::path::Path;
use std::time::Duration;

use super::*;

pub(super) async fn exercise_full_access_trust_revoke(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
) -> (runne_runtime_client::CanonicalId, u64, std::path::PathBuf) {
    eprintln!("RUN: Full Access X2 stops a running process after public trust revoke");
    let listener = LoopbackCapture::new();
    let tag = format!("local-revoke-{}", uuid::Uuid::now_v7());
    let started = project_directory.join(format!("{tag}-started"));
    let release = project_directory.join(format!("{tag}-release"));
    let after_revoke = project_directory.join(format!("{tag}-after-revoke"));
    let script = format!(
        "printf started > '{}'; while [ ! -e '{}' ]; do sleep 0.02; done; printf late >> '{}'; exec 3<>/dev/tcp/127.0.0.1/{}; printf '%s\\n' late >&3; exec 3>&-",
        started.display(),
        release.display(),
        after_revoke.display(),
        listener.port
    );
    let request = local_submit(conversation_id, workspace_id, &tag, &script);
    let task = client
        .submit_task_run(request)
        .await
        .expect("submit running Full Access process")
        .task_run_id();
    assert_no_task_approval(client, task).await;
    wait_for_file(&started).await;

    let workspace = client
        .get_workspace(workspace_id)
        .await
        .expect("read workspace for public trust revoke");
    let current = client
        .get_project_trust(workspace.project_id(), workspace_id)
        .await
        .expect("read current trust revision");
    let revoked = client
        .decide_project_trust(runne_runtime_client::ProjectTrustControlRequestDto {
            project_id: workspace.project_id(),
            workspace_id,
            decision: runne_runtime_client::ProjectTrustDecisionDto::RevokeProject,
            expected_epoch: current.epoch(),
            expected_revision: current.revision(),
            expected_project_version: current.project_version(),
            expected_workspace_version: current.workspace_version(),
            expected_root_admission_version: None,
        })
        .await
        .expect("revoke project trust through public CAS control");
    assert_eq!(
        revoked.status(),
        runne_runtime_client::ProjectTrustStatusDto::Untrusted
    );
    let terminal = wait_for_terminal(client, database, task, &started, &after_revoke).await;
    assert_eq!(terminal.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(terminal.terminal_result(), None);
    assert!(
        has_trust_revoke_terminal_receipt(database, task)
            .expect("read-only trust-revoke stop/terminal receipts"),
        "persisted reason 3 and exact terminal settlement receipt"
    );
    let effects = client
        .get_task_run_effects(task)
        .await
        .expect("read public stopped-process effects");
    let local = effects
        .local_command()
        .expect("public local-command effect");
    assert_eq!(
        local.outcome(),
        runne_runtime_client::LocalExecutionOutcome::Exited
    );
    assert_eq!(
        local.stop(),
        runne_runtime_client::LocalStopEvidence::Confirmed
    );
    std::fs::write(&release, "go").expect("release after the local child stopped");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !after_revoke.exists(),
        "stopped child cannot write after the post-stop release"
    );
    assert!(listener.finish().is_empty());
    (task, terminal.stream_version(), after_revoke)
}

pub(super) fn has_trust_revoke_terminal_receipt(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<bool> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT EXISTS(
               SELECT 1
               FROM taskrun_local_command_attempts a
               JOIN x2_permission_stop s
                 ON s.taskrun_id=a.taskrun_id AND s.attempt_id=a.attempt_id
               JOIN x2_permission_terminal t
                 ON t.taskrun_id=a.taskrun_id AND t.attempt_id=a.attempt_id
                AND t.fence=a.fence
               JOIN taskrun_terminal_settlement_receipts r
                 ON r.taskrun_id=t.taskrun_id AND r.attempt_id=t.attempt_id
                AND r.fence=t.fence AND r.terminal_event_id=t.event_id
                AND r.terminal_version=t.terminal_version
               WHERE a.taskrun_id=?1 AND a.state='cancelled'
                 AND s.reason=3 AND t.terminal_kind=1
             )",
        [id.as_bytes().as_slice()],
        |row| row.get(0),
    )
}
