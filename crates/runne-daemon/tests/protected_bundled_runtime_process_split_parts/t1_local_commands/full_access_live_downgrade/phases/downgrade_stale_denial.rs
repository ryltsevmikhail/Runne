use std::path::Path;

use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "The stale-selection and fresh-denial phase keeps the same-root restart and listener handles."
)]
pub(super) async fn run(
    reopened: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    reopened_client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    executable: &Path,
    session_bus_socket: &Path,
    runtime_root: &Path,
    listener: LoopbackCapture,
    started: &Path,
    late: &Path,
    next_revision: u64,
) {
    let stale_tag = format!("local-live-downgrade-stale-{}", uuid::Uuid::now_v7());
    let stale_started = project_directory.join(format!("{stale_tag}-started"));
    let stale_late = project_directory.join(format!("{stale_tag}-late"));
    let stale_script = format!(
        "printf 'unexpected-start\\n' >> {}; printf 'late\\n' >> {}; exec 3<>/dev/tcp/127.0.0.1/{}; printf 'ask\\n' >&3; exec 3>&-",
        shell_quote_path(&stale_started),
        shell_quote_path(&stale_late),
        listener.port
    );
    let stale_request = local_submit(conversation_id, workspace_id, &stale_tag, &stale_script);
    let stale_task = reopened_client
        .submit_task_run(stale_request.clone())
        .await
        .expect("submit the distinct stale-selection local command")
        .task_run_id();
    let stale_terminal = wait_for_terminal(
        reopened_client,
        database,
        stale_task,
        &stale_started,
        &stale_late,
    )
    .await;
    assert_eq!(
        super::super::super::t1_startup_diagnostic::local_preapproval_diagnostic(runtime_root),
        "current_managed_identity_mismatch",
        "the stale managed identity was rejected before local permission capture"
    );
    assert_stale_selection_failed(
        reopened_client,
        database,
        stale_task,
        &stale_terminal,
        &stale_started,
        &stale_late,
    )
    .await;
    assert_stale_request_replay_is_inert(
        reopened_client,
        database,
        &stale_request,
        stale_task,
        &stale_terminal,
        &stale_started,
        &stale_late,
    )
    .await;

    reopened
        .stop()
        .expect("stop after stale-selection settlement and pre-reopen replay");
    let (mut reopened_again, reopened_again_client) =
        crate::t1_positive::restart_same_root(executable, session_bus_socket, runtime_root).await;
    let mode_after_second_reopen = reopened_again_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read persisted Ask Always after second same-root reopen");
    assert_eq!(
        mode_after_second_reopen.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(
        mode_after_second_reopen.authorization_revision,
        next_revision
    );

    let workspace = reopened_again_client
        .get_workspace(workspace_id)
        .await
        .expect("read workspace before second same-root admission refresh");
    let workspace_api_id = runne_api::WorkspaceId::from_bytes(
        uuid::Uuid::parse_str(&workspace_id.to_string())
            .expect("workspace UUID")
            .into_bytes(),
    );
    let root = runne_platform_desktop::VerifiedRootHandle::open(project_directory)
        .expect("reopen the existing rebound project root handle");
    let admission = reopened_again
        .prepare_root_admission(&root, workspace_api_id, workspace.version())
        .expect("prepare fresh admission for the existing project root after second reopen");
    let admission = runne_runtime_client::ProtectedRootAdmission::from_verified(admission)
        .expect("wrap second-reopen protected root admission");
    let bind_id = runne_runtime_client::CanonicalId::now_v7();
    let bind_identity = runne_runtime_client::CommandIdentity::new(
        bind_id,
        format!("t1-live-downgrade-root-rebind-{bind_id}"),
    )
    .expect("fresh second-reopen root-rebind command identity");
    reopened_again_client
        .bind_workspace_root(
            runne_runtime_client::BindWorkspaceRootRequest::new(
                bind_identity,
                workspace_id,
                workspace.version(),
                &admission,
            )
            .expect("same-project second-reopen root-rebind request"),
        )
        .await
        .expect("bind the existing project root to second process admission");
    let rebound_workspace = reopened_again_client
        .get_workspace(workspace_id)
        .await
        .expect("read workspace after second same-project root rebind");
    let trust = crate::t1_trust_control::grant_through_public_control(
        &reopened_again_client,
        rebound_workspace.project_id(),
        workspace_id,
    )
    .await;
    assert_eq!(
        trust.status(),
        runne_runtime_client::ProjectTrustStatusDto::Trusted
    );
    let mode_after_second_rebind = reopened_again_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read persisted Ask Always after second root rebind");
    assert_eq!(
        mode_after_second_rebind.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(
        mode_after_second_rebind.authorization_revision,
        next_revision
    );

    assert_stale_request_replay_is_inert(
        &reopened_again_client,
        database,
        &stale_request,
        stale_task,
        &stale_terminal,
        &stale_started,
        &stale_late,
    )
    .await;

    let fresh_revision = crate::t1_local_only::change_local_permission_mode(
        &reopened_again_client,
        workspace_id,
        &mut reopened_again,
        runne_api::PermissionModeV1::AskAlways,
    )
    .await;
    assert_eq!(fresh_revision, next_revision + 1);
    let refreshed_mode = reopened_again_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read refreshed Ask Always selection before fresh approval");
    assert_eq!(
        refreshed_mode.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(refreshed_mode.authorization_revision, fresh_revision);

    let fresh_tag = format!("local-live-downgrade-fresh-{}", uuid::Uuid::now_v7());
    let fresh_started = project_directory.join(format!("{fresh_tag}-started"));
    let fresh_late = project_directory.join(format!("{fresh_tag}-late"));
    let fresh_script = format!(
        "printf 'unexpected-start\\n' >> {}; printf 'late\\n' >> {}; exec 3<>/dev/tcp/127.0.0.1/{}; printf 'ask\\n' >&3; exec 3>&-",
        shell_quote_path(&fresh_started),
        shell_quote_path(&fresh_late),
        listener.port
    );
    let fresh_request = local_submit(conversation_id, workspace_id, &fresh_tag, &fresh_script);
    let fresh_task = reopened_again_client
        .submit_task_run(fresh_request)
        .await
        .expect("submit a distinct refreshed Ask Always local command")
        .task_run_id();
    let approval = super::wait_for_approval(&reopened_again_client, fresh_task).await;
    assert_eq!(approval.task_run_id(), fresh_task);
    assert_eq!(approval.action(), "local_command.execute");
    assert!(
        !fresh_started.exists() && !fresh_late.exists(),
        "the distinct Ask Always command has no effect while its exact approval is pending"
    );
    deny_exact(&reopened_again_client, &approval).await;
    let denied = wait_for_terminal(
        &reopened_again_client,
        database,
        fresh_task,
        &fresh_started,
        &fresh_late,
    )
    .await;
    assert_eq!(denied.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(denied.terminal_result(), None);
    let denied_effects = reopened_again_client
        .get_task_run_effects(fresh_task)
        .await
        .expect("read denied refreshed Ask Always effects");
    let denied_local = denied_effects
        .local_command()
        .expect("denied refreshed Ask Always local-command outcome");
    assert_eq!(
        denied_local.outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert_eq!(
        super::local_no_effect_release_facts(database, fresh_task)
            .expect("read-only exact denied no-effect settlement"),
        ("no_effect_terminal".to_owned(), true, 1, 1, 0, 0)
    );
    assert!(
        !fresh_started.exists() && !fresh_late.exists(),
        "denial leaves both separate fresh-task markers absent"
    );
    assert_no_task_approval(&reopened_again_client, fresh_task).await;
    let reopened_denied = reopened_again_client
        .get_task_run(fresh_task)
        .await
        .expect("read denied refreshed Ask Always terminal after cleanup");
    assert_eq!(reopened_denied.stream_version(), denied.stream_version());
    assert_eq!(reopened_denied.terminal_result(), denied.terminal_result());
    assert_started_once(started);
    assert!(!late.exists());
    assert!(!stale_started.exists() && !stale_late.exists());

    reopened_again
        .stop()
        .expect("stop same-root runtime after live-downgrade cleanup");
    assert!(
        listener.finish().is_empty(),
        "the live listener accepted no connections; it does not observe packet delivery"
    );
}
