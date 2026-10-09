pub(in crate::t1_positive::d2_pending) struct CommittedModeSelection {
    mode: runne_api::PermissionModeV1,
    command_id: runne_runtime_client::CanonicalId,
    request: runne_api::PermissionModeChangeRequestV1,
    status: runne_api::PermissionModeCommandStatusV2,
    revision: u64,
}

#[path = "permission_modes/downgrade.rs"]
mod downgrade;
pub(in crate::t1_positive::d2_pending) use downgrade::{
    active_downgrade_barrier, exercise_active_downgrade,
};

pub(in crate::t1_positive::d2_pending) async fn select_replay_and_cancel(
    client: &mut runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
) -> Option<CommittedModeSelection> {
    let Ok(mode_name) = std::env::var("RUNNE_TEST_D2_PERMISSION_MODE") else {
        return None;
    };
    let mode = match mode_name.as_str() {
        "ask_always" => runne_api::PermissionModeV1::AskAlways,
        "risk_based" => runne_api::PermissionModeV1::RiskBased,
        "full_access" => runne_api::PermissionModeV1::FullAccess,
        _ => panic!("unknown D2 permission mode fixture"),
    };
    eprintln!("RUN: D2 permission-mode effect case {mode_name}");
    let before = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read initial permission mode");
    let (command_id, request) = mode_request(workspace_id, before.authorization_revision, mode);
    let initial = client.request_permission_mode_change(request.clone()).await;
    require_pending_or_readback(client, workspace_id, command_id, initial).await;
    commit_current_pending(client, supervisor, command_id).await;

    let committed = client
        .permission_mode_command_status(workspace_id, command_id)
        .await
        .expect("read committed permission-mode command");
    let runne_api::PermissionModeCommandStatusV2::Committed { receipt } = &committed else {
        panic!("native confirmation did not commit selected mode");
    };
    assert_eq!(receipt.selected_mode, mode);
    assert_eq!(
        receipt.authorization_revision,
        before.authorization_revision + 1
    );
    assert_eq!(
        client
            .request_permission_mode_change(request.clone())
            .await
            .expect("replay identical permission-mode command"),
        committed,
        "same command replay returns the original receipt"
    );

    let selected = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read selected mode before cancel");
    assert_eq!(selected.selected_mode, mode);
    let cancel_mode = if mode == runne_api::PermissionModeV1::AskAlways {
        runne_api::PermissionModeV1::RiskBased
    } else {
        runne_api::PermissionModeV1::AskAlways
    };
    let (cancel_id, cancel_request) =
        mode_request(workspace_id, selected.authorization_revision, cancel_mode);
    require_pending(
        client
            .request_permission_mode_change(cancel_request.clone())
            .await,
    );
    let pending = take_pending(client, cancel_id).await;
    supervisor
        .request_permission_mode_challenge(&pending)
        .expect("request authenticated cancel challenge");
    let cancelled = supervisor
        .cancel_permission_mode()
        .expect("cancel native mode change");
    assert!(cancelled.code == runne_api::PermissionControlResultCodeV1::Cancelled);
    assert!(matches!(
        client
            .permission_mode_command_status(workspace_id, cancel_id)
            .await
            .expect("read cancelled mode change"),
        runne_api::PermissionModeCommandStatusV2::Cancelled { .. }
    ));
    assert_eq!(
        client
            .request_permission_mode_change(cancel_request)
            .await
            .expect("replay cancelled mode change"),
        runne_api::PermissionModeCommandStatusV2::Cancelled {
            command_id: domain_command_id(cancel_id),
        }
    );
    let after_cancel = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read mode after cancellation");
    assert_eq!(after_cancel.selected_mode, mode);
    assert_eq!(
        after_cancel.authorization_revision, selected.authorization_revision,
        "cancel leaves the durable selection unchanged"
    );

    let selection = CommittedModeSelection {
        mode,
        command_id,
        request,
        status: committed,
        revision: selected.authorization_revision,
    };
    if active_downgrade_barrier().is_some() {
        None
    } else {
        Some(selection)
    }
}

pub(in crate::t1_positive::d2_pending) async fn assert_reopen_preserves_selection(
    selection: Option<CommittedModeSelection>,
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    runtime_root: &std::path::Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
) {
    let companion_enabled = crate::t1_credential_companion::enabled();
    if companion_enabled {
        assert!(
            selection.is_some(),
            "credential companion requires a committed mode"
        );
    }
    let Some(selection) = selection else {
        return;
    };
    let database = runtime_root.join("runne-daemon/event-log.db");
    let managed_ask_task = if super::super::super::managed_ask::enabled() {
        super::super::super::managed_ask::assert_retained_sidecar(&database);
        let task = super::super::super::managed_ask::task_id();
        let before = client
            .get_task_run(task)
            .await
            .expect("read managed Ask TaskRun before Store reopen");
        assert_eq!(
            before.state(),
            runne_runtime_client::TaskRunState::Succeeded
        );
        Some((task, before.stream_version()))
    } else {
        None
    };
    let before = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read selected mode before Store reopen");
    assert_eq!(before.selected_mode, selection.mode);
    assert_eq!(before.authorization_revision, selection.revision);
    if companion_enabled {
        crate::t1_credential_companion::assert_projection(
            "permission mode before Store reopen",
            &before,
        );
        let committed = client
            .permission_mode_command_status(workspace_id, selection.command_id)
            .await
            .expect("read committed permission-mode projection before Store reopen");
        assert_eq!(committed, selection.status);
        crate::t1_credential_companion::assert_projection(
            "permission-mode receipt before Store reopen",
            &committed,
        );
        let replay = client
            .request_permission_mode_change(selection.request.clone())
            .await
            .expect("replay committed permission-mode projection before Store reopen");
        assert_eq!(replay, selection.status);
        crate::t1_credential_companion::assert_projection(
            "permission-mode replay before Store reopen",
            &replay,
        );
        crate::t1_credential_companion::assert_public_task_and_approvals(
            client,
            workspace_id,
            &database,
            selection.mode,
        )
        .await;
        crate::t1_credential_companion::assert_runtime_tree(runtime_root);
        let (_, (stdout, stderr)) = supervisor
            .stop_capturing_for_test()
            .expect("stop exact captured daemon for mode reopen");
        crate::t1_credential_companion::assert_daemon_output("initial D2 daemon", &stdout, &stderr);
    } else {
        supervisor
            .stop()
            .expect("stop exact daemon for mode reopen");
    }
    let (mut reopened, reopened_client) =
        super::crash::restart_same_root(executable, session_bus_socket, runtime_root).await;
    let reopened_status = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read permission mode after Store reopen");
    assert_eq!(reopened_status.selected_mode, selection.mode);
    assert_eq!(reopened_status.authorization_revision, selection.revision);
    let reopened_receipt = reopened_client
        .permission_mode_command_status(workspace_id, selection.command_id)
        .await
        .expect("read committed receipt after Store reopen");
    assert_eq!(reopened_receipt, selection.status);
    if companion_enabled {
        crate::t1_credential_companion::assert_projection(
            "permission mode after Store reopen",
            &reopened_status,
        );
        crate::t1_credential_companion::assert_projection(
            "permission-mode receipt after Store reopen",
            &reopened_receipt,
        );
    }
    let reopened_replay = reopened_client
        .request_permission_mode_change(selection.request)
        .await
        .expect("replay committed mode after Store reopen");
    assert_eq!(reopened_replay, selection.status);
    if companion_enabled {
        crate::t1_credential_companion::assert_projection(
            "permission-mode replay after Store reopen",
            &reopened_replay,
        );
        crate::t1_credential_companion::assert_public_task_and_approvals(
            &reopened_client,
            workspace_id,
            &database,
            selection.mode,
        )
        .await;
        crate::t1_credential_companion::assert_runtime_tree(runtime_root);
    }
    if let Some((task, stream_version)) = managed_ask_task {
        super::super::super::managed_ask::assert_retained_sidecar(&database);
        let after = reopened_client
            .get_task_run(task)
            .await
            .expect("read managed Ask TaskRun after Store reopen");
        assert_eq!(after.state(), runne_runtime_client::TaskRunState::Succeeded);
        assert_eq!(after.stream_version(), stream_version);
        assert!(
            reopened_client
                .list_pending_approvals()
                .await
                .expect("read approvals after managed Ask reopen")
                .iter()
                .all(|approval| approval.task_run_id() != task),
            "restart did not re-prompt the completed create"
        );
        assert_eq!(super::verify::result_count(&database, task), 2);
        assert_eq!(super::verify::invocation_count(&database, task), 2);
        assert_eq!(super::verify::reserved_effect_count(&database, task), 2);
        assert_eq!(super::verify::release_intent_count(&database, task), 2);
        assert_eq!(
            super::count_watch_mask(
                super::super::super::managed_ask::create_watch(),
                libc::IN_CREATE
            ),
            0,
            "same-root reopen emitted no second create event"
        );
        let create_path = runtime_root
            .parent()
            .expect("runtime root parent")
            .join("rebound-project/fixture-created.txt");
        assert_eq!(
            std::fs::read(create_path).expect("managed Ask create survives reopen"),
            super::CREATE_BYTES
        );
        super::verify::assert_request_counts(runtime_root);
    }
    if companion_enabled {
        let (_, (stdout, stderr)) = reopened
            .stop_capturing_for_test()
            .expect("stop reopened captured D2 runtime");
        crate::t1_credential_companion::assert_daemon_output(
            "reopened D2 daemon",
            &stdout,
            &stderr,
        );
        crate::t1_credential_companion::assert_runtime_tree(runtime_root);
    } else {
        reopened.stop().expect("stop reopened D2 runtime");
    }
}

pub(super) async fn await_create_approval_or_auto_admit(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    create_path: &std::path::Path,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) -> Option<runne_runtime_client::ApprovalSummaryDto> {
    let mode = std::env::var("RUNNE_TEST_D2_PERMISSION_MODE").unwrap_or_default();
    if matches!(mode.as_str(), "risk_based" | "full_access")
        && !super::super::super::managed_ask::enabled()
    {
        super::verify::wait_results(client, database, task, 2, runtime_root).await;
        assert!(
            client
                .list_pending_approvals()
                .await
                .expect("read pending approvals for auto create")
                .iter()
                .all(|approval| approval.task_run_id() != task),
            "auto-admitted create did not produce a human approval"
        );
        assert!(
            create_path.exists(),
            "auto-admitted create took real effect"
        );
        return None;
    }
    let approval = super::approval::wait_approval(client, task, None, database, runtime_root).await;
    assert_eq!(approval.action(), "workspace.tool.invoke");
    assert!(approval.resource().contains("fixture-created.txt"));
    assert!(
        approval
            .risk_summary()
            .contains("workspace.file.create_new")
    );
    assert!(
        !create_path.exists(),
        "Pending create has no filesystem effect"
    );
    Some(approval)
}

async fn commit_current_pending(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    command_id: runne_runtime_client::CanonicalId,
) {
    let pending = take_pending(client, command_id).await;
    supervisor
        .request_permission_mode_challenge(&pending)
        .expect("request exact native permission-mode challenge");
    let result = supervisor
        .test_complete_permission_mode_with_mock_native_authority()
        .expect("complete mock warning/PAM while retaining canonical Store admission");
    assert!(result.code == runne_api::PermissionControlResultCodeV1::Committed);
}

async fn take_pending(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    command_id: runne_runtime_client::CanonicalId,
) -> runne_api::PermissionModeNativePendingV2 {
    client
        .permission_mode_native_pending(None)
        .await
        .expect("read authenticated native pending page")
        .pending
        .into_iter()
        .find(|pending| pending.context.command_id == command_id.to_string())
        .expect("find current command in native pending page")
}

fn mode_request(
    workspace_id: runne_runtime_client::CanonicalId,
    revision: u64,
    mode: runne_api::PermissionModeV1,
) -> (
    runne_runtime_client::CanonicalId,
    runne_api::PermissionModeChangeRequestV1,
) {
    let command_id = runne_runtime_client::CanonicalId::now_v7();
    let workspace = uuid::Uuid::parse_str(&workspace_id.to_string()).expect("workspace UUID");
    let command = uuid::Uuid::parse_str(&command_id.to_string()).expect("command UUID");
    let request = runne_api::PermissionModeChangeRequestV1::new(
        runne_api::WorkspaceId::from_bytes(*workspace.as_bytes()),
        runne_domain::id::CommandId::from_bytes(*command.as_bytes()),
        format!("d2-mode-{}-{command_id}", mode.wire_tag()),
        revision,
        mode,
        1,
        None,
    );
    (command_id, request)
}

fn require_pending<E: std::fmt::Debug>(
    status: Result<runne_api::PermissionModeCommandStatusV2, E>,
) {
    assert!(matches!(
        status.expect("request mode change"),
        runne_api::PermissionModeCommandStatusV2::PendingNativeConfirmation { .. }
            | runne_api::PermissionModeCommandStatusV2::PendingReauthentication { .. }
    ));
}

async fn require_pending_or_readback(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    command_id: runne_runtime_client::CanonicalId,
    status: Result<runne_api::PermissionModeCommandStatusV2, runne_runtime_client::RuntimeApiError>,
) {
    match status {
        Err(error)
            if error.kind() == runne_runtime_client::RuntimeApiErrorKind::UnknownAfterSend =>
        {
            let readback = client
                .permission_mode_command_status(workspace_id, command_id)
                .await;
            let summary = match readback {
                Ok(runne_api::PermissionModeCommandStatusV2::PendingNativeConfirmation {
                    ..
                }) => "pending_native_confirmation",
                Ok(runne_api::PermissionModeCommandStatusV2::PendingReauthentication {
                    ..
                }) => "pending_reauthentication",
                Ok(runne_api::PermissionModeCommandStatusV2::Committed { .. }) => "committed",
                Ok(_) => "terminal",
                Err(error) => panic!("readback error:{:?}", error.kind()),
            };
            panic!("permission-mode POST UnknownAfterSend; one authenticated readback: {summary}");
        }
        result => require_pending(result),
    }
}

fn domain_command_id(id: runne_runtime_client::CanonicalId) -> runne_domain::id::CommandId {
    let bytes = *uuid::Uuid::parse_str(&id.to_string())
        .expect("command UUID")
        .as_bytes();
    runne_domain::id::CommandId::from_bytes(bytes)
}
