use super::CommittedModeSelection;

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
    let managed_ask_task = if super::super::super::super::managed_ask::enabled() {
        super::super::super::super::managed_ask::assert_retained_sidecar(&database);
        let task = super::super::super::super::managed_ask::task_id();
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
        super::super::crash::restart_same_root(executable, session_bus_socket, runtime_root).await;
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
        super::super::super::super::managed_ask::assert_retained_sidecar(&database);
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
        assert_eq!(super::super::verify::result_count(&database, task), 2);
        assert_eq!(super::super::verify::invocation_count(&database, task), 2);
        assert_eq!(
            super::super::verify::reserved_effect_count(&database, task),
            2
        );
        assert_eq!(
            super::super::verify::release_intent_count(&database, task),
            2
        );
        assert_eq!(
            super::super::count_watch_mask(
                super::super::super::super::managed_ask::create_watch(),
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
            super::super::CREATE_BYTES
        );
        super::super::verify::assert_request_counts(runtime_root);
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
