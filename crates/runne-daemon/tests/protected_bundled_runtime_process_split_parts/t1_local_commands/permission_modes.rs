use std::{
    io::Read as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    time::Duration,
};

use super::super::t1_local_only::{LoopbackCapture, wait_for_file};

#[path = "full_access_live_downgrade.rs"]
mod full_access_live_downgrade;
#[path = "legacy_selection.rs"]
mod legacy_selection;
#[path = "network_matrix.rs"]
mod network_matrix;
#[path = "path_process_matrix.rs"]
mod path_process_matrix;
#[path = "shell_corpus.rs"]
mod shell_corpus;
#[path = "unavailable_network.rs"]
mod unavailable_network;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &Path,
    session_bus_socket: &Path,
    runtime_root: &Path,
    mode: runne_api::PermissionModeV1,
) {
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_UNAVAILABLE_NETWORK").is_some() {
        assert_eq!(mode, runne_api::PermissionModeV1::FullAccess);
        unavailable_network::exercise(
            client,
            conversation_id,
            workspace_id,
            project_directory,
            database,
            supervisor,
            executable,
            session_bus_socket,
            runtime_root,
        )
        .await;
        return;
    }
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_LEGACY_SELECTION").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        assert_eq!(mode, runne_api::PermissionModeV1::RiskBased);
        legacy_selection::exercise(
            client,
            conversation_id,
            workspace_id,
            project_directory,
            database,
            supervisor,
            executable,
            session_bus_socket,
            runtime_root,
        )
        .await;
        return;
    }
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_FULL_ACCESS_LIVE_DOWNGRADE").is_some() {
        assert_eq!(mode, runne_api::PermissionModeV1::FullAccess);
        full_access_live_downgrade::exercise(
            client,
            conversation_id,
            workspace_id,
            project_directory,
            database,
            supervisor,
            executable,
            session_bus_socket,
            runtime_root,
        )
        .await;
        return;
    }
    eprintln!("RUN: real local-command X2 effects for {mode:?}");
    let selected_mode = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read selected permission mode before local TaskRuns");
    assert_eq!(selected_mode.selected_mode, mode);
    if let Ok(case) = std::env::var("RUNNE_TEST_T1_LOCAL_PRECAPTURE_FAILURE_CASE") {
        assert_eq!(mode, runne_api::PermissionModeV1::AskAlways);
        exercise_precapture_failure(
            client,
            conversation_id,
            workspace_id,
            project_directory,
            database,
            supervisor,
            executable,
            session_bus_socket,
            runtime_root,
            &case,
            selected_mode.authorization_revision,
        )
        .await;
        return;
    }
    let listener = LoopbackCapture::new();
    let payload = format!("local-mode-{}", uuid::Uuid::now_v7());
    let before_network = project_directory.join(format!("{payload}-before-network"));
    let after_network = project_directory.join(format!("{payload}-after-network"));
    let filesystem = PermissionModeFilesystemMatrix::new(project_directory, &payload);
    let path_process = path_process_matrix::PathProcessMatrix::new(project_directory, &payload);
    let shell_corpus = shell_corpus::ShellCorpus::new(project_directory, &payload);
    let mut network = network_matrix::NetworkMatrix::new(
        project_directory,
        &payload,
        mode == runne_api::PermissionModeV1::FullAccess,
    );
    let script = format!(
        "set -e; {}; {}; {}; {}; printf '%s\\n' '{payload}' >> {}; exec 3<>/dev/tcp/127.0.0.1/{} 2>/dev/null || exit 42; printf '%s\\n' '{payload}' >&3; exec 3>&-; printf '%s\\n' after >> {}",
        filesystem.shell_script(),
        path_process.shell_script(),
        shell_corpus.shell_script(),
        network.shell_script(),
        shell_quote_path(&before_network),
        listener.port,
        shell_quote_path(&after_network)
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
        let approval = wait_for_approval(client, task).await;
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
    let payloads = listener.finish();
    assert_eq!(
        payloads,
        if allows_network {
            vec![format!("{payload}\n").into_bytes()]
        } else {
            vec![]
        }
    );
    assert_no_task_approval(client, task).await;
    let denied = if mode != runne_api::PermissionModeV1::FullAccess {
        Some(
            exercise_local_no_effect_case(
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
                LocalNoEffectResolution::Deny,
            )
            .await,
        )
    } else {
        None
    };
    let expired = if mode == runne_api::PermissionModeV1::AskAlways {
        Some(
            exercise_local_no_effect_case(
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
                LocalNoEffectResolution::Expire,
            )
            .await,
        )
    } else {
        None
    };
    let mode_changed = if mode == runne_api::PermissionModeV1::RiskBased {
        Some(
            exercise_local_no_effect_case(
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
                LocalNoEffectResolution::ChangeMode(&mut *supervisor),
            )
            .await,
        )
    } else {
        None
    };
    let revoke = if allows_network {
        Some(
            exercise_full_access_trust_revoke(
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
            )
            .await,
        )
    } else {
        None
    };

    let expected_mode = if mode_changed.is_some() {
        runne_api::PermissionModeV1::AskAlways
    } else {
        mode
    };
    let final_mode = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read final permission mode before same-root reopen");
    assert_eq!(final_mode.selected_mode, expected_mode);
    assert_eq!(
        final_mode.authorization_revision,
        selected_mode.authorization_revision + if mode_changed.is_some() { 1 } else { 0 }
    );

    supervisor
        .stop()
        .expect("stop exact local permission-mode daemon for same-root reopen");
    let (mut reopened, reopened_client) =
        super::super::t1_positive::restart_same_root(executable, session_bus_socket, runtime_root)
            .await;
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
    assert_changed_intents_conflict(&reopened_client, &changed_intents).await;
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

    let before_contents = std::fs::read_to_string(&before_network)
        .expect("re-read real pre-network file effect after reopen");
    filesystem.assert_effects();
    path_process.assert_effects();
    shell_corpus.assert_effects();
    network.assert_records();
    assert_eq!(before_contents, format!("{payload}\n"));
    assert_eq!(
        before_contents
            .lines()
            .filter(|line| *line == payload.as_str())
            .count(),
        1,
        "same local TaskRun leaves exactly one filesystem effect after reopen"
    );
    assert_eq!(after_network.exists(), allows_network);
    if allows_network {
        assert_eq!(std::fs::read_to_string(&after_network).unwrap(), "after\n");
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

const WORKSPACE_READ_PROOF: &str = "workspace-read-proof";
const SIBLING_READ_PROOF: &str = "sibling-read-proof";
const WORKSPACE_APPEND_SEED: &str = "workspace-append-before\n";
const SIBLING_APPEND_SEED: &str = "sibling-append-before\n";

struct PermissionModeFilesystemMatrix {
    workspace_read: PathBuf,
    workspace_append: PathBuf,
    workspace_create: PathBuf,
    workspace_delete: PathBuf,
    sibling_directory: PathBuf,
    sibling_read: PathBuf,
    sibling_append: PathBuf,
    sibling_create: PathBuf,
    sibling_delete: PathBuf,
}

impl PermissionModeFilesystemMatrix {
    fn new(project_directory: &Path, payload: &str) -> Self {
        let sibling_directory = project_directory
            .parent()
            .expect("fixture workspace has a parent directory")
            .join(format!("{payload}-outside-workspace"));
        std::fs::create_dir(&sibling_directory).expect("create fixture sibling directory");
        let matrix = Self {
            workspace_read: project_directory.join(format!("{payload}-workspace-read")),
            workspace_append: project_directory.join(format!("{payload}-workspace-append")),
            workspace_create: project_directory.join(format!("{payload}-workspace-create")),
            workspace_delete: project_directory.join(format!("{payload}-workspace-delete")),
            sibling_read: sibling_directory.join("read-seed"),
            sibling_append: sibling_directory.join("append-seed"),
            sibling_create: sibling_directory.join("created-output"),
            sibling_delete: sibling_directory.join("delete-canary"),
            sibling_directory,
        };
        std::fs::write(&matrix.workspace_read, format!("{WORKSPACE_READ_PROOF}\n"))
            .expect("seed workspace read proof");
        std::fs::write(&matrix.workspace_append, WORKSPACE_APPEND_SEED)
            .expect("seed workspace append file");
        std::fs::write(&matrix.workspace_delete, "workspace-delete-canary\n")
            .expect("seed workspace delete canary");
        std::fs::write(&matrix.sibling_read, format!("{SIBLING_READ_PROOF}\n"))
            .expect("seed sibling read proof");
        std::fs::write(&matrix.sibling_append, SIBLING_APPEND_SEED)
            .expect("seed sibling append file");
        std::fs::write(&matrix.sibling_delete, "sibling-delete-canary\n")
            .expect("seed sibling delete canary");
        assert!(
            !matrix.workspace_create.exists() && !matrix.sibling_create.exists(),
            "create targets start absent"
        );
        matrix
    }

    fn shell_script(&self) -> String {
        let workspace_read = shell_quote_path(&self.workspace_read);
        let workspace_append = shell_quote_path(&self.workspace_append);
        let workspace_create = shell_quote_path(&self.workspace_create);
        let workspace_delete = shell_quote_path(&self.workspace_delete);
        let sibling_read = shell_quote_path(&self.sibling_read);
        let sibling_append = shell_quote_path(&self.sibling_append);
        let sibling_create = shell_quote_path(&self.sibling_create);
        let sibling_delete = shell_quote_path(&self.sibling_delete);
        format!(
            "test \"$(cat -- {workspace_read})\" = '{WORKSPACE_READ_PROOF}'; cat -- {workspace_read} >> {workspace_append}; printf '%s\\n' 'workspace-created-content' > {workspace_create}; rm -- {workspace_delete}; test \"$(cat -- {sibling_read})\" = '{SIBLING_READ_PROOF}'; cat -- {sibling_read} >> {sibling_append}; printf '%s\\n' 'sibling-created-content' > {sibling_create}; rm -- {sibling_delete}"
        )
    }

    fn assert_pending(&self, before_network: &Path, after_network: &Path) {
        assert!(self.sibling_directory.is_dir());
        assert_eq!(
            std::fs::read_to_string(&self.workspace_read).unwrap(),
            format!("{WORKSPACE_READ_PROOF}\n")
        );
        assert_eq!(
            std::fs::read_to_string(&self.workspace_append).unwrap(),
            WORKSPACE_APPEND_SEED
        );
        assert_eq!(
            std::fs::read_to_string(&self.workspace_delete).unwrap(),
            "workspace-delete-canary\n"
        );
        assert_eq!(
            std::fs::read_to_string(&self.sibling_read).unwrap(),
            format!("{SIBLING_READ_PROOF}\n")
        );
        assert_eq!(
            std::fs::read_to_string(&self.sibling_append).unwrap(),
            SIBLING_APPEND_SEED
        );
        assert_eq!(
            std::fs::read_to_string(&self.sibling_delete).unwrap(),
            "sibling-delete-canary\n"
        );
        assert!(
            !self.workspace_create.exists()
                && !self.sibling_create.exists()
                && !before_network.exists()
                && !after_network.exists(),
            "pending process has no filesystem outputs"
        );
    }

    fn assert_effects(&self) {
        assert_eq!(
            std::fs::read_to_string(&self.workspace_read).unwrap(),
            format!("{WORKSPACE_READ_PROOF}\n"),
            "the workspace read seed remains unchanged"
        );
        assert_eq!(
            std::fs::read_to_string(&self.workspace_append).unwrap(),
            format!("{WORKSPACE_APPEND_SEED}{WORKSPACE_READ_PROOF}\n"),
            "workspace read bytes were appended exactly once"
        );
        assert_eq!(
            std::fs::read_to_string(&self.workspace_create).unwrap(),
            "workspace-created-content\n"
        );
        assert!(!self.workspace_delete.exists());
        assert_eq!(
            std::fs::read_to_string(&self.sibling_read).unwrap(),
            format!("{SIBLING_READ_PROOF}\n"),
            "the sibling read seed remains unchanged"
        );
        assert_eq!(
            std::fs::read_to_string(&self.sibling_append).unwrap(),
            format!("{SIBLING_APPEND_SEED}{SIBLING_READ_PROOF}\n"),
            "sibling read bytes were appended exactly once"
        );
        assert_eq!(
            std::fs::read_to_string(&self.sibling_create).unwrap(),
            "sibling-created-content\n"
        );
        assert!(!self.sibling_delete.exists());
    }
}

fn shell_quote_path(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing carries the real supervisor, root, and public runtime client together."
)]
async fn exercise_precapture_failure(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &Path,
    session_bus_socket: &Path,
    runtime_root: &Path,
    case: &str,
    authorization_revision: u64,
) {
    eprintln!("RUN: local pre-capture {case} removal after claim");
    let tag = format!("local-precapture-{}", uuid::Uuid::now_v7());
    let helper_relative = format!("{tag}-helper");
    let helper_path = project_directory.join(&helper_relative);
    let marker = project_directory.join(format!("{tag}-marker"));
    let listener = LoopbackCapture::new();
    let script = format!(
        "#!/bin/bash\nprintf '%s\\n' '{tag}' > \"$RUNNE_TEST_MARKER_PATH\"\nexec 3<>/dev/tcp/127.0.0.1/{} 2>/dev/null || exit 42\nprintf '%s\\n' '{tag}' >&3\nexec 3>&-\n",
        listener.port
    );
    std::fs::write(&helper_path, script).expect("create real workspace executable");
    std::fs::set_permissions(&helper_path, std::fs::Permissions::from_mode(0o755))
        .expect("make workspace helper executable");

    let (cwd, removed_path, expected_absent) = match case {
        "executable" => (".".to_owned(), helper_path.clone(), helper_path.clone()),
        "cwd" => {
            let cwd = format!("{tag}-cwd");
            let path = project_directory.join(&cwd);
            std::fs::create_dir(&path).expect("create real local-command cwd");
            (cwd, path.clone(), path)
        }
        _ => panic!("unknown local pre-capture failure fixture"),
    };
    assert!(helper_path.is_file());
    if case == "cwd" {
        assert!(removed_path.is_dir());
    }
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::workspace_relative(helper_relative.clone())
            .expect("valid workspace-relative executable"),
        cwd,
        vec!["precapture-fixture".into()],
        vec![(
            "RUNNE_TEST_MARKER_PATH".into(),
            marker.display().to_string(),
        )],
    )
    .expect("valid local pre-capture command");
    let request = runne_runtime_client::SubmitTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-local-precapture-{case}-{tag}"),
        )
        .expect("local pre-capture command identity"),
        conversation_id,
        workspace_id,
        format!("Exercise local pre-capture {case} failure"),
    )
    .expect("valid local pre-capture TaskRun")
    .with_local_command(command)
    .expect("select local pre-capture command");
    let task = client
        .submit_task_run(request.clone())
        .await
        .expect("submit workspace-relative local command")
        .task_run_id();

    let (entered, release) = wait_for_local_capture_barrier(database, task).await;
    assert!(
        local_precapture_claim_facts(database, task)
            .expect("read exact claimed preflight state while capture is held"),
        "barrier is reached after one exact active claim, before local capture"
    );
    assert_eq!(
        local_precapture_authority_facts(database, task)
            .expect("read empty permission authority while capture is held"),
        (0, 0, 0, 0, 0, 0)
    );
    assert!(entered.is_file());
    assert!(expected_absent.exists());
    assert!(!marker.exists());

    match case {
        "executable" => std::fs::remove_file(&removed_path).expect("delete claimed executable"),
        "cwd" => std::fs::remove_dir(&removed_path).expect("delete claimed cwd"),
        _ => unreachable!(),
    }
    assert!(!removed_path.exists());
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&release)
        .expect("release exact local pre-capture barrier");

    let terminal = wait_for_terminal(client, database, task, &marker, &removed_path).await;
    assert_eq!(terminal.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(terminal.terminal_result(), None);
    assert_eq!(
        client
            .get_task_run_effects(task)
            .await
            .expect("read failed pre-capture local projection")
            .local_command()
            .expect("pre-capture local command outcome")
            .outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert_eq!(
        local_no_effect_release_facts(database, task)
            .expect("read exact pre-capture release receipt"),
        ("no_effect_terminal".to_owned(), true, 0, 1, 0, 0),
        "pre-capture failure releases the exact absent-dispatch occupation without a captured binding"
    );
    assert_eq!(
        local_precapture_authority_facts(database, task)
            .expect("read pre-capture authority absence"),
        (0, 0, 0, 0, 0, 0),
        "capture, human admission, native admission, spend, stop, and permission terminal are absent"
    );
    assert_no_task_approval(client, task).await;
    assert!(!marker.exists());
    assert!(!removed_path.exists());

    let selected = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read Ask Always before same-root reopen");
    assert_eq!(
        selected.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(selected.authorization_revision, authorization_revision);
    supervisor
        .stop()
        .expect("stop daemon before pre-capture same-root reopen");
    let (mut reopened, reopened_client) =
        super::super::t1_positive::restart_same_root(executable, session_bus_socket, runtime_root)
            .await;
    let reopened_mode = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read Ask Always after same-root reopen");
    assert_eq!(reopened_mode.selected_mode, selected.selected_mode);
    assert_eq!(
        reopened_mode.authorization_revision,
        selected.authorization_revision
    );
    let replay = reopened_client
        .submit_task_run(request)
        .await
        .expect("replay exact pre-capture submission after reopen");
    assert_eq!(replay.task_run_id(), task);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let reread = reopened_client
        .get_task_run(task)
        .await
        .expect("read pre-capture TaskRun after reopen and replay");
    assert_eq!(reread.state(), terminal.state());
    assert_eq!(reread.stream_version(), terminal.stream_version());
    assert_eq!(reread.terminal_result(), terminal.terminal_result());
    assert_eq!(
        reopened_client
            .get_task_run_effects(task)
            .await
            .expect("read pre-capture effects after reopen")
            .local_command()
            .expect("retained pre-capture local projection")
            .outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert_eq!(
        local_no_effect_release_facts(database, task)
            .expect("re-read exact pre-capture release receipt after reopen"),
        ("no_effect_terminal".to_owned(), true, 0, 1, 0, 0)
    );
    assert_eq!(
        local_precapture_authority_facts(database, task)
            .expect("re-read pre-capture authority absence after reopen"),
        (0, 0, 0, 0, 0, 0)
    );
    assert_no_task_approval(&reopened_client, task).await;
    assert!(!marker.exists());
    assert!(!removed_path.exists());
    assert!(
        listener.finish().is_empty(),
        "pre-capture failure and replay produce no loopback network effect"
    );
    reopened
        .stop()
        .expect("stop reopened pre-capture fixture daemon");
}

async fn wait_for_local_capture_barrier(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let directory = std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR")
        .expect("parent supplies the local pre-capture barrier directory");
    let directory = Path::new(&directory);
    let entered = directory.join("claimed-before-area.entered");
    let release = directory.join("claimed-before-area.release");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(9);
    while !entered.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "local capture claim barrier timed out: durable claim facts={:?}",
            local_precapture_claim_facts(database, task)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (entered, release)
}

struct LocalNoEffectCase {
    task: runne_runtime_client::CanonicalId,
    version: u64,
    before: std::path::PathBuf,
    after: std::path::PathBuf,
    mode_change: bool,
}

enum LocalNoEffectResolution<'a> {
    Deny,
    Expire,
    ChangeMode(&'a mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor),
}

async fn exercise_local_no_effect_case(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    resolution: LocalNoEffectResolution<'_>,
) -> LocalNoEffectCase {
    let mode_change = matches!(&resolution, LocalNoEffectResolution::ChangeMode(_));
    let listener = LoopbackCapture::new();
    let tag = format!(
        "local-mode-{}-{}",
        match &resolution {
            LocalNoEffectResolution::Deny => "denied",
            LocalNoEffectResolution::Expire => "expired",
            LocalNoEffectResolution::ChangeMode(_) => "mode-changed",
        },
        uuid::Uuid::now_v7()
    );
    let before = project_directory.join(format!("{tag}-before-network"));
    let after = project_directory.join(format!("{tag}-after-network"));
    let script = format!(
        "printf '%s\\n' '{tag}' >> '{}'; exec 3<>/dev/tcp/127.0.0.1/{} 2>/dev/null || exit 42; printf '%s\\n' '{tag}' >&3; exec 3>&-; printf '%s\\n' after >> '{}'",
        before.display(),
        listener.port,
        after.display()
    );
    let task = client
        .submit_task_run(local_submit(conversation_id, workspace_id, &tag, &script))
        .await
        .expect("submit local command awaiting a public approval decision")
        .task_run_id();
    let approval = wait_for_approval(client, task).await;
    assert_eq!(approval.action(), "local_command.execute");
    assert!(!before.exists() && !after.exists());
    match resolution {
        LocalNoEffectResolution::Deny => deny_exact(client, &approval).await,
        LocalNoEffectResolution::Expire => expire_exact(client, &approval).await,
        LocalNoEffectResolution::ChangeMode(supervisor) => {
            assert_eq!(
                client
                    .permission_mode_status(workspace_id)
                    .await
                    .expect("read Risk Based mode while exact process approval is pending")
                    .selected_mode,
                runne_api::PermissionModeV1::RiskBased
            );
            crate::t1_local_only::change_local_permission_mode(
                client,
                workspace_id,
                supervisor,
                runne_api::PermissionModeV1::AskAlways,
            )
            .await;
            let acknowledgement = approve_exact(client, &approval).await;
            assert_eq!(
                acknowledgement.state(),
                runne_runtime_client::ApprovalStateDto::Approved,
                "mode change preserves the exact pending approval as an auditable stale record"
            );
            assert_eq!(
                client
                    .get_approval(approval.approval_id())
                    .await
                    .expect("read accepted exact approval after mode change")
                    .state(),
                runne_runtime_client::ApprovalStateDto::Approved
            );
        }
    }

    let terminal = wait_for_terminal(client, database, task, &before, &after).await;
    assert_eq!(terminal.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(terminal.terminal_result(), None);
    let effects = client
        .get_task_run_effects(task)
        .await
        .expect("read public no-effect projection");
    assert_eq!(
        effects
            .local_command()
            .expect("no-effect local-command outcome")
            .outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert_eq!(
        local_no_effect_release_facts(database, task)
            .expect("read-only exact no-effect release evidence"),
        ("no_effect_terminal".to_owned(), true, 1, 1, 0, 0),
        "one canonical capture and released absent-dispatch receipt, with no legacy approval authority, spent row, or dispatch row"
    );
    if mode_change {
        assert_eq!(
            local_permission_stop_facts(database, task)
                .expect("read exact local mode-change stop reason"),
            (1, Some(2)),
            "canonical Ask Always selection change stops the captured Risk Based admission"
        );
    }
    assert!(!before.exists() && !after.exists());
    assert!(listener.finish().is_empty());
    assert_no_task_approval(client, task).await;
    LocalNoEffectCase {
        task,
        version: terminal.stream_version(),
        before,
        after,
        mode_change,
    }
}

async fn expire_exact(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    approval: &runne_runtime_client::ApprovalSummaryDto,
) {
    let expiry = u64::try_from(approval.expires_at()).expect("positive local approval expiry");
    let now = unix_millis();
    assert!(expiry > now, "local approval is genuinely pending");
    assert!(
        expiry - now <= 120_000,
        "local approval has its bounded lifetime"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(130);
    while unix_millis() <= expiry {
        assert!(
            tokio::time::Instant::now() < deadline,
            "approval did not expire"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let expired = client
        .get_approval(approval.approval_id())
        .await
        .expect("read expired local command approval");
    assert_eq!(
        expired.state(),
        runne_runtime_client::ApprovalStateDto::Expired
    );
    let late = runne_runtime_client::ApprovalDecisionRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("late-approve-local-mode-{}", approval.approval_id()),
        )
        .expect("late approval identity"),
        approval.approval_id(),
        approval.request_version(),
        runne_runtime_client::ApprovalDecisionDto::Approve,
        *approval.action_digest(),
        approval.policy_revision(),
        1,
    )
    .expect("late exact approval request");
    assert!(
        client.decide_approval(late).await.is_err(),
        "expired approval cannot be revived"
    );
    let still_expired = client
        .get_approval(approval.approval_id())
        .await
        .expect("read approval after rejected late decision");
    assert_eq!(
        still_expired.state(),
        runne_runtime_client::ApprovalStateDto::Expired
    );
}

async fn assert_reopened_no_effect_case(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &Path,
    case: &LocalNoEffectCase,
    label: &str,
) {
    let task = client
        .get_task_run(case.task)
        .await
        .expect("read no-effect TaskRun after same-root reopen");
    assert_eq!(task.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(task.stream_version(), case.version);
    assert_eq!(task.terminal_result(), None);
    assert_eq!(
        client
            .get_task_run_effects(case.task)
            .await
            .expect("read retained no-effect local projection after reopen")
            .local_command()
            .expect("retained no-effect local command")
            .outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert!(
        !case.before.exists() && !case.after.exists(),
        "{label} process leaves no files after reopen"
    );
    assert_eq!(
        local_no_effect_release_facts(database, case.task)
            .expect("re-read exact no-effect release evidence after reopen"),
        ("no_effect_terminal".to_owned(), true, 1, 1, 0, 0),
        "same no-effect proof persists with no legacy approval authority after reopen"
    );
    if case.mode_change {
        assert_eq!(
            local_permission_stop_facts(database, case.task)
                .expect("re-read exact mode-change stop reason after reopen"),
            (1, Some(2)),
            "reason 2 no-effect settlement persists across reopen"
        );
    }
}

async fn exercise_full_access_trust_revoke(
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

fn human_admission_count(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<i64> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT COUNT(*)
           FROM taskrun_local_command_attempts a
           JOIN x2_permission_human h ON h.taskrun_id=a.taskrun_id AND h.attempt_id=a.attempt_id
           JOIN x2_permission_admission p
             ON p.taskrun_id=h.taskrun_id AND p.attempt_id=h.attempt_id
            AND p.binding_digest=h.binding_digest AND p.proof_digest=h.proof_digest
          WHERE a.taskrun_id=?1 AND p.admission_kind=2",
        [id.as_bytes().as_slice()],
        |row| row.get(0),
    )
}

fn local_no_effect_release_facts(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<(String, bool, i64, i64, i64, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT a.state,
                a.approval_id IS NULL,
                (SELECT COUNT(*) FROM x2_permission_bindings b
                  JOIN taskrun_local_permission_routes p USING(taskrun_id)
                 WHERE b.taskrun_id=a.taskrun_id AND b.attempt_id=a.attempt_id
                   AND p.route=2 AND p.provenance=3 AND p.cutover_version=68),
                (SELECT COUNT(*) FROM taskrun_no_effect_release_receipts n
                  JOIN taskrun_assignment_occupations o
                    ON o.taskrun_id=n.taskrun_id AND o.fence=n.fence
                   AND o.attempt_id=n.attempt_id
                  JOIN events e ON e.event_id=n.failure_event_id
                 WHERE n.taskrun_id=a.taskrun_id AND n.attempt_id=a.attempt_id
                   AND o.state='released' AND o.dispatch_intent='absent'
                   AND o.release_event_id=n.failure_event_id
                   AND e.aggregate_type=1 AND e.aggregate_id=n.taskrun_id
                   AND e.sequence=n.new_version),
                (SELECT COUNT(*) FROM x2_permission_spent s WHERE s.taskrun_id=a.taskrun_id),
                (SELECT COUNT(*) FROM taskrun_dispatch_intents d WHERE d.taskrun_id=a.taskrun_id)
           FROM taskrun_local_command_attempts a WHERE a.taskrun_id=?1",
        [id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )
}

fn local_precapture_authority_facts(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<(i64, i64, i64, i64, i64, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT (SELECT COUNT(*) FROM x2_permission_bindings WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM x2_permission_human WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM x2_permission_admission WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM x2_permission_spent WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM x2_permission_stop WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM x2_permission_terminal WHERE taskrun_id=?1)",
        [id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )
}

fn local_precapture_claim_facts(
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
             FROM taskrun_claim_receipts c
             JOIN taskrun_assignment_occupations o
               ON o.taskrun_id=c.taskrun_id AND o.fence=c.fence AND o.attempt_id=c.attempt_id
             JOIN taskrun_local_command_attempts a ON a.taskrun_id=c.taskrun_id
             WHERE c.taskrun_id=?1 AND c.new_version>0
               AND (SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1)=1
               AND o.state='active' AND o.dispatch_intent='absent'
               AND a.state='preflight' AND a.attempt_id IS NULL
               AND a.approval_id IS NULL AND a.executable_digest IS NULL
         )",
        [id.as_bytes().as_slice()],
        |row| row.get(0),
    )
}

fn local_permission_stop_facts(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<(i64, Option<i64>)> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT COUNT(*), MAX(s.reason)
           FROM x2_permission_stop s
           JOIN taskrun_local_command_attempts a
             ON a.taskrun_id=s.taskrun_id AND a.attempt_id=s.attempt_id
          WHERE a.taskrun_id=?1",
        [id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
}

fn has_trust_revoke_terminal_receipt(
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

fn local_submit(
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    key: &str,
    script: &str,
) -> runne_runtime_client::SubmitTaskRunRequest {
    let command = runne_api::TaskRunLocalCommand::new(
        runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
        ".".into(),
        vec!["bash".into(), "-c".into(), script.to_owned()],
        Vec::new(),
    )
    .expect("valid structured local command");
    runne_runtime_client::SubmitTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-local-mode-{key}"),
        )
        .unwrap(),
        conversation_id,
        workspace_id,
        format!("Run one local permission-mode effect {key}"),
    )
    .unwrap()
    .with_local_command(command)
    .unwrap()
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}

async fn wait_for_approval(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
) -> runne_runtime_client::ApprovalSummaryDto {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(approval) = client
            .list_pending_approvals()
            .await
            .expect("list local process approvals")
            .into_iter()
            .find(|approval| approval.task_run_id() == task)
        {
            return approval;
        }
        if tokio::time::Instant::now() >= deadline {
            let task_run = client.get_task_run(task).await.expect("public TaskRun");
            let state_reason = (task_run.state(), task_run.terminal_result());
            panic!("state+reason: {state_reason:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn approve_exact(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    approval: &runne_runtime_client::ApprovalSummaryDto,
) -> runne_runtime_client::ApprovalDecisionAcknowledgementDto {
    client
        .decide_approval(
            runne_runtime_client::ApprovalDecisionRequest::new(
                runne_runtime_client::CommandIdentity::new(
                    runne_runtime_client::CanonicalId::now_v7(),
                    format!("approve-local-mode-{}", approval.approval_id()),
                )
                .unwrap(),
                approval.approval_id(),
                approval.request_version(),
                runne_runtime_client::ApprovalDecisionDto::Approve,
                *approval.action_digest(),
                approval.policy_revision(),
                1,
            )
            .expect("exact local invocation approval"),
        )
        .await
        .expect("approve exact local invocation")
}

async fn deny_exact(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    approval: &runne_runtime_client::ApprovalSummaryDto,
) {
    let decision = runne_runtime_client::ApprovalDecisionRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("deny-local-mode-{}", approval.approval_id()),
        )
        .unwrap(),
        approval.approval_id(),
        approval.request_version(),
        runne_runtime_client::ApprovalDecisionDto::Deny,
        *approval.action_digest(),
        approval.policy_revision(),
        1,
    )
    .expect("exact version-bound local-command denial");
    assert_eq!(
        client
            .decide_approval(decision)
            .await
            .expect("deny exact local-command approval through public API")
            .state(),
        runne_runtime_client::ApprovalStateDto::Denied
    );
}

async fn assert_no_task_approval(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
) {
    assert!(
        client
            .list_pending_approvals()
            .await
            .expect("read pending local approvals")
            .iter()
            .all(|approval| approval.task_run_id() != task),
        "TaskRun has no pending human approval"
    );
}

async fn assert_changed_intents_conflict(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    requests: &[runne_runtime_client::SubmitTaskRunRequest],
) {
    for (index, request) in requests.iter().enumerate() {
        let error = match client.submit_task_run(request.clone()).await {
            Ok(_) => panic!("changed local-command intent {index} was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            runne_runtime_client::RuntimeApiErrorKind::Conflict,
            "changed local-command intent {index} returns a stable conflict"
        );
    }
}

async fn wait_for_terminal(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &Path,
    task: runne_runtime_client::CanonicalId,
    first_effect: &Path,
    second_effect: &Path,
) -> runne_runtime_client::TaskRunSnapshot {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let current = client.get_task_run(task).await.expect("read local TaskRun");
        if matches!(
            current.state(),
            runne_runtime_client::TaskRunState::Succeeded
                | runne_runtime_client::TaskRunState::Failed
                | runne_runtime_client::TaskRunState::Cancelled
                | runne_runtime_client::TaskRunState::BudgetExhausted
                | runne_runtime_client::TaskRunState::PolicyDenied
                | runne_runtime_client::TaskRunState::Unrecoverable
        ) {
            return current;
        }
        if tokio::time::Instant::now() >= deadline {
            let local = client
                .get_task_run_effects(task)
                .await
                .map(|effects| {
                    effects
                        .local_command()
                        .map(|local| (local.outcome(), local.stop(), local.exit_code()))
                })
                .map_err(|error| error.kind());
            let durable = durable_local_diagnostic(database, task);
            let store_stage = local_store_diagnostic_stage(database);
            let runtime_root = database.parent().and_then(Path::parent);
            let local_preapproval_stage = runtime_root
                .map(super::super::t1_startup_diagnostic::local_preapproval_diagnostic)
                .unwrap_or_else(|| "unrecognized".to_owned());
            let runtime_root_permissions_masked = runtime_root
                .and_then(|root| std::fs::metadata(root).ok())
                .map(|metadata| metadata.permissions().mode() & 0o077);
            panic!(
                "local TaskRun did not settle: state={:?}; terminal={:?}; local={local:?}; durable={durable:?}; store_stage={store_stage}; local_preapproval_stage={local_preapproval_stage}; runtime_root_permissions_masked_0o077={runtime_root_permissions_masked:?}; files=({}, {})",
                current.state(),
                current.terminal_result(),
                first_effect.exists(),
                second_effect.exists()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn local_store_diagnostic_stage(database: &Path) -> String {
    let Some(runtime_root) = database.parent().and_then(Path::parent) else {
        return "unrecognized".to_owned();
    };
    let path = runtime_root.join(".runne-test-store-diagnostic-stage");
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return "absent".to_owned();
        }
        Err(_) => return "unrecognized".to_owned(),
    };
    let mut stage = String::new();
    if file.take(65).read_to_string(&mut stage).is_err() || stage.len() > 64 {
        return "unrecognized".to_owned();
    }
    let stage = stage.strip_suffix('\n').unwrap_or(&stage);
    match stage {
        "no_effect.capture"
        | "no_effect.claim"
        | "no_effect.occupation"
        | "no_effect.runtime_evidence"
        | "no_effect.release"
        | "no_effect.mark" => stage.to_owned(),
        _ => "unrecognized".to_owned(),
    }
}

fn durable_local_diagnostic(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> Option<String> {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    let id = uuid::Uuid::parse_str(&task.to_string()).ok()?.into_bytes();
    connection
        .query_row(
            "SELECT a.state,
                    (SELECT COUNT(*) FROM x2_permission_admission WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM x2_permission_human WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM x2_permission_spent WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM x2_permission_stop WHERE taskrun_id=?1),
                    (SELECT reason FROM x2_permission_stop WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM x2_permission_terminal WHERE taskrun_id=?1)
             FROM taskrun_local_command_attempts a WHERE a.taskrun_id=?1",
            [id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .map(|(state, admission, human, spent, stop, stop_reason, terminal)| {
            format!(
                "attempt_state={state}; admission={admission}; human={human}; spent={spent}; stop={stop}; stop_reason={stop_reason:?}; terminal={terminal}"
            )
        })
        .ok()
}
