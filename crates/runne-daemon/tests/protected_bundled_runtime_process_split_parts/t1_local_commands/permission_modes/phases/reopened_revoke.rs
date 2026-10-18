use std::path::{Path, PathBuf};

use super::network_matrix::NetworkMatrix;
use super::path_process_matrix::PathProcessMatrix;
use super::shell_corpus::ShellCorpus;
use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "The reopened-runtime phase keeps the exact task, request, matrices, and receipts together."
)]
pub(super) async fn run(
    executable: &Path,
    session_bus_socket: &Path,
    runtime_root: &Path,
    workspace_id: runne_runtime_client::CanonicalId,
    database: &Path,
    mode: runne_api::PermissionModeV1,
    allows_network: bool,
    final_mode: &runne_api::PermissionModeStatusV1,
    task: runne_runtime_client::CanonicalId,
    request: &runne_runtime_client::SubmitTaskRunRequest,
    changed_intents: &[runne_runtime_client::SubmitTaskRunRequest],
    payload: &str,
    before_network: &Path,
    after_network: &Path,
    filesystem: &PermissionModeFilesystemMatrix,
    path_process: &PathProcessMatrix,
    shell_corpus: &ShellCorpus,
    mut network: NetworkMatrix,
    terminal: &runne_runtime_client::TaskRunSnapshot,
    local_facts: (
        runne_runtime_client::LocalExecutionOutcome,
        runne_runtime_client::LocalStopEvidence,
        Option<i32>,
    ),
    denied: Option<LocalNoEffectCase>,
    expired: Option<LocalNoEffectCase>,
    mode_changed: Option<LocalNoEffectCase>,
    revoke: Option<(runne_runtime_client::CanonicalId, u64, PathBuf)>,
) {
    let (mut reopened, reopened_client) =
        crate::t1_positive::restart_same_root(executable, session_bus_socket, runtime_root).await;
    let reopened_mode = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read permission mode after same-root reopen");
    assert_eq!(reopened_mode.selected_mode, final_mode.selected_mode);
    assert_eq!(
        reopened_mode.authorization_revision,
        final_mode.authorization_revision
    );
    let reopened_task = reopened_client
        .get_task_run(task)
        .await
        .expect("read existing local TaskRun after same-root reopen");
    assert_eq!(reopened_task.state(), terminal.state());
    assert_eq!(reopened_task.stream_version(), terminal.stream_version());
    assert_eq!(reopened_task.terminal_result(), terminal.terminal_result());
    let reopened_effects = reopened_client
        .get_task_run_effects(task)
        .await
        .expect("read existing local effects after same-root reopen");
    let reopened_local = reopened_effects
        .local_command()
        .expect("retained public local-command effect after reopen");
    assert_eq!(
        (
            reopened_local.outcome(),
            reopened_local.stop(),
            reopened_local.exit_code()
        ),
        local_facts
    );
    let reopened_replay = reopened_client
        .submit_task_run(request.clone())
        .await
        .expect("replay exact local TaskRun after same-root reopen");
    assert_eq!(reopened_replay.task_run_id(), task);
    assert_changed_intents_conflict(&reopened_client, changed_intents).await;
    shell_corpus.assert_effects();
    let unchanged_reopened_task = reopened_client
        .get_task_run(task)
        .await
        .expect("read local TaskRun after reopened changed-intent conflicts");
    assert_eq!(unchanged_reopened_task.state(), terminal.state());
    assert_eq!(
        unchanged_reopened_task.stream_version(),
        terminal.stream_version()
    );
    assert_eq!(
        unchanged_reopened_task.terminal_result(),
        terminal.terminal_result()
    );
    let unchanged_reopened_effects = reopened_client
        .get_task_run_effects(task)
        .await
        .expect("read local effect facts after reopened changed-intent conflicts");
    let unchanged_reopened_local = unchanged_reopened_effects
        .local_command()
        .expect("retained local effect after reopened changed-intent conflicts");
    assert_eq!(
        (
            unchanged_reopened_local.outcome(),
            unchanged_reopened_local.stop(),
            unchanged_reopened_local.exit_code()
        ),
        local_facts
    );

    let before_contents = std::fs::read_to_string(before_network)
        .expect("re-read real pre-network file effect after reopen");
    filesystem.assert_effects();
    path_process.assert_effects();
    shell_corpus.assert_effects();
    network.assert_records();
    assert_eq!(before_contents, format!("{payload}\n"));
    assert_eq!(
        before_contents
            .lines()
            .filter(|line| *line == payload)
            .count(),
        1,
        "same local TaskRun leaves exactly one filesystem effect after reopen"
    );
    assert_eq!(after_network.exists(), allows_network);
    if allows_network {
        assert_eq!(std::fs::read_to_string(after_network).unwrap(), "after\n");
    }
    network.shutdown();
    drop(network);
    if mode != runne_api::PermissionModeV1::FullAccess {
        assert_eq!(
            human_admission_count(database, task).expect("read exact human admission after reopen"),
            1,
            "human approval proof is durably joined to this TaskRun admission"
        );
    }

    if let Some(denied) = denied.as_ref() {
        assert_reopened_no_effect_case(&reopened_client, database, denied, "denied").await;
    }
    if let Some(expired) = expired.as_ref() {
        assert_reopened_no_effect_case(&reopened_client, database, expired, "expired").await;
    }
    if let Some(mode_changed) = mode_changed.as_ref() {
        assert_reopened_no_effect_case(&reopened_client, database, mode_changed, "mode-changed")
            .await;
    }

    if let Some((revoke_task, revoke_version, after_revoke)) = revoke {
        let reopened_revoke = reopened_client
            .get_task_run(revoke_task)
            .await
            .expect("read existing trust-revoked TaskRun after same-root reopen");
        assert_eq!(
            reopened_revoke.state(),
            runne_runtime_client::TaskRunState::Failed
        );
        assert_eq!(reopened_revoke.stream_version(), revoke_version);
        assert_eq!(reopened_revoke.terminal_result(), None);
        assert!(
            has_trust_revoke_terminal_receipt(database, revoke_task)
                .expect("re-read trust-revoke stop/settlement receipt after reopen"),
            "reason 3 stop and exact terminal settlement persist across reopen"
        );
        let reopened_revoke_effects = reopened_client
            .get_task_run_effects(revoke_task)
            .await
            .expect("read trust-revoked process effects after reopen");
        let reopened_revoke_local = reopened_revoke_effects
            .local_command()
            .expect("retained trust-revoked local effect after reopen");
        assert_eq!(
            reopened_revoke_local.outcome(),
            runne_runtime_client::LocalExecutionOutcome::Exited
        );
        assert_eq!(
            reopened_revoke_local.stop(),
            runne_runtime_client::LocalStopEvidence::Confirmed
        );
        assert!(
            !after_revoke.exists(),
            "stopped child still has no late file effect after reopen"
        );
    }
    reopened.stop().expect("stop same-root reopened D2 runtime");
}
