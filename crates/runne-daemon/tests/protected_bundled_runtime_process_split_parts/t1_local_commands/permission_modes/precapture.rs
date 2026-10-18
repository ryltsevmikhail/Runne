use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing carries the real supervisor, root, and public runtime client together."
)]
pub(super) async fn exercise_precapture_failure(
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
        crate::t1_positive::restart_same_root(executable, session_bus_socket, runtime_root).await;
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
