use std::path::{Path, PathBuf};

use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "The fixture needs the exact runtime root, public client, and same-root restart handles."
)]
pub(super) async fn run(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &Path,
    session_bus_socket: &Path,
    runtime_root: &Path,
) -> (
    runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    runne_runtime_client::AuthenticatedRuntimeClient,
    LoopbackCapture,
    PathBuf,
    PathBuf,
    u64,
) {
    eprintln!("RUN: Full Access live downgrade with the fixture's explicit mock native authority");
    let initial_mode = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read exact Full Access selection before live downgrade");
    assert_eq!(
        initial_mode.selected_mode,
        runne_api::PermissionModeV1::FullAccess
    );

    let listener = LoopbackCapture::new();
    let tag = format!("local-live-downgrade-{}", uuid::Uuid::now_v7());
    let started = project_directory.join(format!("{tag}-started"));
    let gate = project_directory.join(format!("{tag}-gate"));
    let late = project_directory.join(format!("{tag}-late"));
    let script = format!(
        "printf 'started\\n' >> {}; while [ ! -e {} ]; do sleep 0.02; done; printf 'late\\n' >> {}; exec 3<>/dev/tcp/127.0.0.1/{}; printf 'late\\n' >&3; exec 3>&-",
        shell_quote_path(&started),
        shell_quote_path(&gate),
        shell_quote_path(&late),
        listener.port
    );
    let request = local_submit(conversation_id, workspace_id, &tag, &script);
    let task = client
        .submit_task_run(request.clone())
        .await
        .expect("submit one Full Access local command at its captured revision")
        .task_run_id();
    wait_for_file(&started).await;
    assert_eq!(
        std::fs::read_to_string(&started).expect("read started marker before downgrade"),
        "started\n",
        "the child appended its one started marker before permission changed"
    );
    assert!(!gate.exists() && !late.exists());
    assert_no_task_approval(client, task).await;

    let next_revision = crate::t1_local_only::change_local_permission_mode(
        client,
        workspace_id,
        supervisor,
        runne_api::PermissionModeV1::AskAlways,
    )
    .await;
    assert_eq!(next_revision, initial_mode.authorization_revision + 1);
    let downgraded_mode = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read Ask Always selection after live downgrade");
    assert_eq!(
        downgraded_mode.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(downgraded_mode.authorization_revision, next_revision);

    let terminal = wait_for_terminal(client, database, task, &started, &late).await;
    assert_eq!(terminal.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(terminal.terminal_result(), None);
    let effects = client
        .get_task_run_effects(task)
        .await
        .expect("read public live-downgrade process effect");
    let local = effects
        .local_command()
        .expect("public live-downgrade local-command effect");
    let local_facts = (local.outcome(), local.stop(), local.exit_code());
    assert_eq!(
        local_facts.0,
        runne_runtime_client::LocalExecutionOutcome::Exited
    );
    assert_eq!(
        local_facts.1,
        runne_runtime_client::LocalStopEvidence::Confirmed
    );
    let receipt = read_downgrade_receipt(database, task);
    assert_downgrade_receipt(&receipt, task);
    assert_no_task_approval(client, task).await;

    // The fixture releases the child only after its stop is publicly confirmed.
    std::fs::write(&gate, "release after confirmed stop\n").expect("release stopped child gate");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_started_once(&started);
    assert!(
        !late.exists(),
        "confirmed stop prevents the gated late write"
    );

    assert_replay_is_inert(
        client,
        database,
        &request,
        task,
        &terminal,
        local_facts,
        &receipt,
        &started,
        &late,
    )
    .await;

    supervisor
        .stop()
        .expect("gracefully stop exact live-downgrade runtime before same-root reopen");
    let (mut reopened, reopened_client) =
        crate::t1_positive::restart_same_root(executable, session_bus_socket, runtime_root).await;
    let reopened_mode = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read persisted Ask Always selection after same-root reopen");
    assert_eq!(
        reopened_mode.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(reopened_mode.authorization_revision, next_revision);
    assert_replay_is_inert(
        &reopened_client,
        database,
        &request,
        task,
        &terminal,
        local_facts,
        &receipt,
        &started,
        &late,
    )
    .await;

    // Restart replaces process-local protected root handles; rebind this same
    // already-selected project root before asking for a new local approval.
    let workspace = reopened_client
        .get_workspace(workspace_id)
        .await
        .expect("read workspace before same-root admission refresh");
    let workspace_api_id = runne_api::WorkspaceId::from_bytes(
        uuid::Uuid::parse_str(&workspace_id.to_string())
            .expect("workspace UUID")
            .into_bytes(),
    );
    let root = runne_platform_desktop::VerifiedRootHandle::open(project_directory)
        .expect("reopen the existing rebound project root handle");
    let admission = reopened
        .prepare_root_admission(&root, workspace_api_id, workspace.version())
        .expect("prepare fresh admission for the existing project root");
    let admission = runne_runtime_client::ProtectedRootAdmission::from_verified(admission)
        .expect("wrap fresh protected root admission");
    let bind_id = runne_runtime_client::CanonicalId::now_v7();
    let bind_identity = runne_runtime_client::CommandIdentity::new(
        bind_id,
        format!("t1-live-downgrade-root-rebind-{bind_id}"),
    )
    .expect("fresh root-rebind command identity");
    reopened_client
        .bind_workspace_root(
            runne_runtime_client::BindWorkspaceRootRequest::new(
                bind_identity,
                workspace_id,
                workspace.version(),
                &admission,
            )
            .expect("same-project root-rebind request"),
        )
        .await
        .expect("bind the existing project root to fresh process admission");
    let rebound_workspace = reopened_client
        .get_workspace(workspace_id)
        .await
        .expect("read workspace after same-project root rebind");
    let trust = crate::t1_trust_control::grant_through_public_control(
        &reopened_client,
        rebound_workspace.project_id(),
        workspace_id,
    )
    .await;
    assert_eq!(
        trust.status(),
        runne_runtime_client::ProjectTrustStatusDto::Trusted
    );
    let mode_after_rebind = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read Ask Always selection after root rebind");
    assert_eq!(
        mode_after_rebind.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(mode_after_rebind.authorization_revision, next_revision);

    (
        reopened,
        reopened_client,
        listener,
        started,
        late,
        next_revision,
    )
}
