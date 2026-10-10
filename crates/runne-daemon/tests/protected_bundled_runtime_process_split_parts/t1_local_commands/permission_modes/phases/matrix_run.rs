use std::path::{Path, PathBuf};

use super::filesystem_matrix::shell_quote_relative;
use super::network_matrix::NetworkMatrix;
use super::path_process_matrix::PathProcessMatrix;
use super::shell_corpus::ShellCorpus;
use super::*;

pub(super) async fn run(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    mode: runne_api::PermissionModeV1,
) -> (
    LoopbackCapture,
    PermissionModeFilesystemMatrix,
    PathProcessMatrix,
    ShellCorpus,
    NetworkMatrix,
    PathBuf,
    PathBuf,
    String,
    runne_runtime_client::SubmitTaskRunRequest,
    Vec<runne_runtime_client::SubmitTaskRunRequest>,
    runne_runtime_client::CanonicalId,
    runne_runtime_client::TaskRunSnapshot,
    (
        runne_runtime_client::LocalExecutionOutcome,
        runne_runtime_client::LocalStopEvidence,
        Option<i32>,
    ),
    bool,
) {
    let listener = LoopbackCapture::new();
    let payload = format!("local-mode-{}", uuid::Uuid::now_v7());
    let before_network = project_directory.join(format!("{payload}-before-network"));
    let after_network = project_directory.join(format!("{payload}-after-network"));
    let filesystem = PermissionModeFilesystemMatrix::new(project_directory, &payload);
    let path_process = path_process_matrix::PathProcessMatrix::new(project_directory, &payload);
    let shell_corpus = shell_corpus::ShellCorpus::new(project_directory, &payload);
    let network = network_matrix::NetworkMatrix::new(
        project_directory,
        &payload,
        mode == runne_api::PermissionModeV1::FullAccess,
    );
    let fixture_cwd = path_process.cwd();
    let script = format!(
        "set -e; {}; {}; {}; {}; printf '%s\\n' '{payload}' >> {}; exec 3<>/dev/tcp/127.0.0.1/{} 2>/dev/null || exit 42; printf '%s\\n' '{payload}' >&3; exec 3>&-; printf '%s\\n' after >> {}",
        filesystem.shell_script(fixture_cwd),
        path_process.shell_script(),
        shell_corpus.shell_script(fixture_cwd),
        network.shell_script(fixture_cwd),
        shell_quote_relative(fixture_cwd, &before_network),
        listener.port,
        shell_quote_relative(fixture_cwd, &after_network)
    );
    // Deterministic regression: the daemon renders this argv verbatim into a
    // bounded (4096-byte) approval review. The script therefore must never
    // embed absolute fixture paths (whose depth varies between a dev shell
    // and the canonical CI execution namespace) nor grow unbounded.
    assert!(
        !script.contains(&project_directory.display().to_string()),
        "matrix script must stay independent of the fixture temp-path depth"
    );
    assert!(
        script.len() < 3072,
        "matrix script must keep the rendered approval review below the \
         4096-byte bound (4096 minus the ~1 KiB JSON wrapper); len={}",
        script.len()
    );
    let request = path_process.request(conversation_id, workspace_id, &payload, &script);
    let changed_intents = path_process.changed_intent_requests(&request, &script);
    let task = client
        .submit_task_run(request.clone())
        .await
        .expect("submit one local X2 effect invocation")
        .task_run_id();

    if mode == runne_api::PermissionModeV1::FullAccess {
        wait_for_file(&before_network).await;
        filesystem.assert_effects();
        path_process.assert_effects();
        shell_corpus.assert_effects();
    } else {
        let approval = wait_for_approval(client, task, database).await;
        assert_eq!(approval.action(), "local_command.execute");
        filesystem.assert_pending(&before_network, &after_network);
        path_process.assert_pending();
        shell_corpus.assert_pending();
        network.assert_pending();
        let pending_task = client
            .get_task_run(task)
            .await
            .expect("read local TaskRun while approval is pending");
        let pending_replay = client
            .submit_task_run(request.clone())
            .await
            .expect("replay exact local TaskRun while approval is pending");
        assert_eq!(pending_replay.task_run_id(), task);
        assert_changed_intents_conflict(client, &changed_intents).await;
        let unchanged_approval = client
            .get_approval(approval.approval_id())
            .await
            .expect("read original approval after changed-intent conflicts");
        assert_eq!(unchanged_approval.approval_id(), approval.approval_id());
        assert_eq!(unchanged_approval.action_digest(), approval.action_digest());
        assert_eq!(
            unchanged_approval.request_version(),
            approval.request_version()
        );
        assert_eq!(
            unchanged_approval.state(),
            runne_runtime_client::ApprovalStateDto::Pending
        );
        let unchanged_task = client
            .get_task_run(task)
            .await
            .expect("read pending local TaskRun after changed-intent conflicts");
        assert_eq!(
            unchanged_task.stream_version(),
            pending_task.stream_version()
        );
        filesystem.assert_pending(&before_network, &after_network);
        path_process.assert_pending();
        shell_corpus.assert_pending();
        network.assert_pending();
        assert_eq!(
            approve_exact(client, &approval).await.state(),
            runne_runtime_client::ApprovalStateDto::Approved
        );
    }

    let terminal = wait_for_terminal(client, database, task, &before_network, &after_network).await;
    filesystem.assert_effects();
    path_process.assert_effects();
    shell_corpus.assert_effects();
    network.assert_records();
    let allows_network = mode == runne_api::PermissionModeV1::FullAccess;
    if allows_network {
        assert_eq!(
            terminal.state(),
            runne_runtime_client::TaskRunState::Succeeded
        );
        assert!(matches!(
            terminal.terminal_result(),
            Some(runne_runtime_client::TaskRunTerminalResult::Success)
        ));
        assert_eq!(std::fs::read_to_string(&after_network).unwrap(), "after\n");
    } else {
        assert_eq!(
            terminal.state(),
            runne_runtime_client::TaskRunState::Succeeded
        );
        assert!(matches!(
            terminal.terminal_result(),
            Some(runne_runtime_client::TaskRunTerminalResult::Failure { reason })
                if reason == "local_command_exit_42"
        ));
        assert!(!after_network.exists());
    }
    assert_eq!(
        std::fs::read_to_string(&before_network).unwrap(),
        format!("{payload}\n"),
        "the real filesystem write before a denied socket remains visible"
    );
    let effects = client
        .get_task_run_effects(task)
        .await
        .expect("read public local process outcome");
    let local = effects.local_command().expect("local X2 effect receipt");
    assert_eq!(
        local.outcome(),
        runne_runtime_client::LocalExecutionOutcome::Exited
    );
    assert_eq!(local.exit_code(), Some(if allows_network { 0 } else { 42 }));
    let local_facts = (local.outcome(), local.stop(), local.exit_code());

    let replay = client
        .submit_task_run(request.clone())
        .await
        .expect("replay the identical TaskRun submission");
    assert_eq!(
        replay.task_run_id(),
        task,
        "replay keeps one TaskRun identity"
    );
    assert_changed_intents_conflict(client, &changed_intents).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let reread = client
        .get_task_run(task)
        .await
        .expect("read terminal TaskRun after replay");
    assert_eq!(reread.stream_version(), terminal.stream_version());
    assert_eq!(
        std::fs::read_to_string(&before_network).unwrap(),
        format!("{payload}\n"),
        "replay produces no second filesystem effect"
    );
    filesystem.assert_effects();
    path_process.assert_effects();
    shell_corpus.assert_effects();
    network.assert_records();

    (
        listener,
        filesystem,
        path_process,
        shell_corpus,
        network,
        before_network,
        after_network,
        payload,
        request,
        changed_intents,
        task,
        terminal,
        local_facts,
        allows_network,
    )
}
