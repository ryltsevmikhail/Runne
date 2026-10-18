use std::future::Future;
use std::time::Duration;

use runne_api::{
    PermissionControlResultCodeV1, PermissionControlResultV1, PermissionModeCommandStatusV2,
    PermissionModeNativePendingV2,
};
use runne_app_core::AppCore;
use tauri::{AppHandle, Manager as _};

use super::{readback_matches, status_belongs_to_pending_command};

pub(super) async fn wait_for_command_terminal(
    app: &AppHandle,
    core: &AppCore,
    pending: &PermissionModeNativePendingV2,
    expected_result: Option<&PermissionControlResultV1>,
) -> bool {
    wait_for_terminal(
        pending,
        expected_result,
        || async move {
            core.permission_mode_command_status(&pending.workspace_id, &pending.context.command_id)
                .await
                .map_err(|_| ())
        },
        || {
            app.try_state::<crate::RuntimeLifecycleManager>()
                .is_some_and(|lifecycle| lifecycle.is_shutting_down())
        },
        Duration::from_secs(1),
    )
    .await
}

pub(super) async fn wait_for_terminal<F, Fut, S>(
    pending: &PermissionModeNativePendingV2,
    expected_result: Option<&PermissionControlResultV1>,
    mut read_status: F,
    mut shutting_down: S,
    poll_interval: Duration,
) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<PermissionModeCommandStatusV2, ()>>,
    S: FnMut() -> bool,
{
    loop {
        if shutting_down() {
            return false;
        }
        if let Ok(status) = read_status().await
            && terminal_status(&status)
            && status_belongs_to_pending_command(&status, pending)
        {
            let matches_result = match expected_result {
                None => true,
                Some(result) if result.code == PermissionControlResultCodeV1::Pending => {
                    result_matches_pending(result, pending)
                }
                Some(result) => readback_matches(result, &status, pending),
            };
            if matches_result {
                return true;
            }
        }
        tokio::time::sleep(poll_interval).await;
    }
}

const fn terminal_status(status: &PermissionModeCommandStatusV2) -> bool {
    matches!(
        status,
        PermissionModeCommandStatusV2::Committed { .. }
            | PermissionModeCommandStatusV2::Cancelled { .. }
            | PermissionModeCommandStatusV2::Expired { .. }
            | PermissionModeCommandStatusV2::Invalidated { .. }
    )
}

fn result_matches_pending(
    result: &PermissionControlResultV1,
    pending: &PermissionModeNativePendingV2,
) -> bool {
    uuid::Uuid::from_bytes(result.command_id).to_string() == pending.context.command_id
        && result.public_request_digest == pending.context.public_request_digest
}
