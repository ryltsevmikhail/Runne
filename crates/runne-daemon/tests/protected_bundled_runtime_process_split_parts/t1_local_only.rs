use std::{
    io::Read as _,
    net::TcpListener,
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};

use super::t1_taskrun_support::LocalTaskRunContext;

pub(super) struct LoopbackCapture {
    pub(super) port: String,
    stop: Sender<()>,
    join: thread::JoinHandle<Vec<Vec<u8>>>,
}

pub(super) async fn wait_for_file(path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !path.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "local process did not start"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

impl LoopbackCapture {
    pub(super) fn new() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback effect listener");
        let port = listener.local_addr().unwrap().port().to_string();
        listener.set_nonblocking(true).unwrap();
        let (stop, stopped): (Sender<()>, Receiver<()>) = mpsc::channel();
        let join = thread::spawn(move || {
            let mut payloads = Vec::new();
            let mut stopping = false;
            loop {
                stopping |= stopped.try_recv().is_ok();
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut payload = Vec::new();
                        let _ = stream.read_to_end(&mut payload);
                        payloads.push(payload);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && stopping => {
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            payloads
        });
        Self { port, stop, join }
    }

    pub(super) fn finish(self) -> Vec<Vec<u8>> {
        let _ = self.stop.send(());
        self.join.join().expect("join loopback capture")
    }
}

pub(super) async fn exercise_if_requested(mut context: LocalTaskRunContext<'_>) {
    let selected_mode = select_local_permission_mode(
        &mut context.client,
        context.workspace_id,
        context.supervisor,
    )
    .await;
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_CRASH_ONLY").is_some() {
        super::t1_local_crash_recovery::exercise_daemon_crash_recovery(&mut context, selected_mode)
            .await;
        return;
    }
    if let Some(mode) = selected_mode {
        super::t1_local_commands::exercise_permission_mode_effects(
            &context.client,
            context.conversation_id,
            context.workspace_id,
            context.project_directory,
            context.database,
            context.supervisor,
            context.executable.path(),
            context.session_bus_socket,
            context.runtime_root,
            mode,
        )
        .await;
        return;
    }
    if super::t1_local_barrier::exercise_if_requested(&mut context).await {
        context
            .supervisor
            .stop()
            .expect("stop daemon after local barrier scenario");
        return;
    }
    super::t1_local_commands::exercise_local_commands(
        &context.client,
        context.conversation_id,
        context.workspace_id,
        context.project_directory,
        context.database,
        context.runtime_root,
    )
    .await;
    super::t1_local_cancel::exercise_running_cancel(
        &context.client,
        context.conversation_id,
        context.workspace_id,
        context.project_directory,
        context.database,
    )
    .await;
    let (recovered_client, mut recovered_supervisor) =
        super::t1_local_restart_cancel::exercise_restart_during_local_cancel(
            context,
            std::env::var_os("RUNNE_TEST_T1_LOCAL_MISSING_AREA").is_some(),
        )
        .await;
    drop(recovered_client);
    recovered_supervisor
        .stop()
        .expect("stop daemon after cancellation restart test");
}

async fn select_local_permission_mode(
    client: &mut runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
) -> Option<runne_api::PermissionModeV1> {
    let mode = match std::env::var("RUNNE_TEST_D2_PERMISSION_MODE") {
        Ok(value) => match value.as_str() {
            "ask_always" => runne_api::PermissionModeV1::AskAlways,
            "risk_based" => runne_api::PermissionModeV1::RiskBased,
            "full_access" => runne_api::PermissionModeV1::FullAccess,
            _ => panic!("unknown local permission-mode fixture"),
        },
        Err(_) => return None,
    };
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_LEGACY_SELECTION").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        return Some(runne_api::PermissionModeV1::RiskBased);
    }
    change_local_permission_mode(client, workspace_id, supervisor, mode).await;
    Some(mode)
}

pub(super) async fn change_local_permission_mode(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    mode: runne_api::PermissionModeV1,
) -> u64 {
    let before = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read initial local permission mode");
    let command_id = runne_runtime_client::CanonicalId::now_v7();
    let workspace = uuid::Uuid::parse_str(&workspace_id.to_string()).expect("workspace UUID");
    let command = uuid::Uuid::parse_str(&command_id.to_string()).expect("command UUID");
    let request = runne_api::PermissionModeChangeRequestV1::new(
        runne_api::WorkspaceId::from_bytes(*workspace.as_bytes()),
        runne_domain::id::CommandId::from_bytes(*command.as_bytes()),
        format!("t1-local-mode-{}-{command_id}", mode.wire_tag()),
        before.authorization_revision,
        mode,
        1,
        None,
    );
    let status = client.request_permission_mode_change(request).await;
    let status = match status {
        Ok(status) => status,
        Err(error)
            if error.kind() == runne_runtime_client::RuntimeApiErrorKind::UnknownAfterSend =>
        {
            let readback = client
                .permission_mode_command_status(workspace_id, command_id)
                .await;
            panic!(
                "local mode POST UnknownAfterSend; one authenticated readback: {}",
                bounded_local_mode_readback(readback)
            );
        }
        Err(error) => panic!(
            "request authenticated local mode change failed: {:?}",
            error.kind()
        ),
    };
    assert!(matches!(
        status,
        runne_api::PermissionModeCommandStatusV2::PendingNativeConfirmation { .. }
    ));
    let pending = client
        .permission_mode_native_pending(None)
        .await
        .expect("read authenticated local native-pending page")
        .pending
        .into_iter()
        .find(|pending| pending.context.command_id == command_id.to_string())
        .expect("find the exact local mode command");
    supervisor
        .request_permission_mode_challenge(&pending)
        .expect("request canonical native mode challenge");
    let completed = supervisor
        .test_complete_permission_mode_with_mock_native_authority()
        .expect("complete explicit mock warning/PAM through Store admission");
    assert!(completed.code == runne_api::PermissionControlResultCodeV1::Committed);
    let selected = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read committed local permission mode");
    assert_eq!(selected.selected_mode, mode);
    assert_eq!(
        selected.authorization_revision,
        before.authorization_revision + 1
    );
    selected.authorization_revision
}

fn bounded_local_mode_readback(
    result: Result<runne_api::PermissionModeCommandStatusV2, runne_runtime_client::RuntimeApiError>,
) -> String {
    match result {
        Ok(runne_api::PermissionModeCommandStatusV2::PendingNativeConfirmation { .. }) => {
            "pending_native_confirmation".to_owned()
        }
        Ok(runne_api::PermissionModeCommandStatusV2::PendingReauthentication { .. }) => {
            "pending_reauthentication".to_owned()
        }
        Ok(runne_api::PermissionModeCommandStatusV2::Committed { .. }) => "committed".to_owned(),
        Ok(runne_api::PermissionModeCommandStatusV2::Cancelled { .. }) => "cancelled".to_owned(),
        Ok(runne_api::PermissionModeCommandStatusV2::Expired { .. }) => "expired".to_owned(),
        Ok(runne_api::PermissionModeCommandStatusV2::Invalidated { .. }) => {
            "invalidated".to_owned()
        }
        Err(error) => format!("error:{:?}", error.kind()),
    }
}
