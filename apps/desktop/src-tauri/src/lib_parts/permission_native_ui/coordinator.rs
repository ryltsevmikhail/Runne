use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use runne_api::{
    PermissionControlResultCodeV1, PermissionModeCommandStatusV2, PermissionModeSelectionV1,
};
use runne_app_core::{AppCore, CanonicalId};
use runne_platform_desktop::permission_reauth_linux::{
    self, MAX_REAUTH_WINDOW, PamConversationHandler,
};
use tauri::{AppHandle, Manager as _, WebviewWindow};

use crate::bundled_runtime::BundledRuntimeController;

use super::bridge::NativeWarningScheduler;
use super::gtk_dialog::GtkPamConversationHandler as GtkPamHandler;

#[path = "recovery.rs"]
mod recovery;

#[expect(
    clippy::redundant_pub_crate,
    reason = "The private UI module re-exports this worker only within the app crate."
)]
pub(crate) fn start(app: AppHandle, core: Arc<AppCore>, controller: Arc<BundledRuntimeController>) {
    tauri::async_runtime::spawn(async move {
        loop {
            if app
                .try_state::<crate::RuntimeLifecycleManager>()
                .is_some_and(|lifecycle| lifecycle.is_shutting_down())
            {
                break;
            }
            if let Some(window) = app
                .get_webview_window("main")
                .filter(|window| window.is_visible().unwrap_or(false))
                && pull_pending(&app, &core, &controller, window)
                    .await
                    .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

async fn pull_pending(
    app: &AppHandle,
    core: &AppCore,
    controller: &BundledRuntimeController,
    window: WebviewWindow,
) -> Result<(), ()> {
    let mut cursor = None;
    loop {
        let Ok(page) = core.permission_mode_native_pending(cursor).await else {
            return Ok(());
        };
        for pending in page.pending {
            if !process_pending(app, core, controller, &window, pending).await? {
                return Ok(());
            }
        }
        let Some(next) = page.next_cursor else {
            return Ok(());
        };
        let Ok(next) = CanonicalId::parse(&next) else {
            return Ok(());
        };
        cursor = Some(next);
    }
}

async fn process_pending(
    app: &AppHandle,
    core: &AppCore,
    controller: &BundledRuntimeController,
    window: &WebviewWindow,
    pending: runne_api::PermissionModeNativePendingV2,
) -> Result<bool, ()> {
    if !native_ui_available(app, window) {
        return Ok(false);
    }
    let Ok(challenge) = controller
        .request_permission_mode_challenge(pending.clone())
        .await
    else {
        return Ok(recovery::wait_for_command_terminal(app, core, &pending, None).await);
    };
    if !native_ui_available(app, window) {
        finish_cancelled(app, core, controller, &pending).await?;
        return Ok(false);
    }
    let Ok(context) = pending.context.control_context() else {
        finish_cancelled(app, core, controller, &pending).await?;
        return Ok(true);
    };
    let scheduler = NativeWarningScheduler::new(window.clone());
    let ui_challenge = challenge.clone();
    let ui_scheduler = scheduler;
    let ui_context = context.clone();
    let warning = tauri::async_runtime::spawn_blocking(move || {
        permission_reauth_linux::request_native_permission_warning(
            &ui_challenge,
            &ui_context,
            &ui_scheduler,
        )
    })
    .await
    .ok()
    .and_then(Result::ok);
    let Some(warning) = warning else {
        finish_cancelled(app, core, controller, &pending).await?;
        return Ok(native_ui_available(app, window));
    };
    if !native_ui_available(app, window) {
        finish_cancelled(app, core, controller, &pending).await?;
        return Ok(false);
    }
    let os_reauthentication = if challenge.requested_mode == PermissionModeSelectionV1::FullAccess {
        let Some(token) = fresh_os_evidence(window.clone(), challenge.clone()).await else {
            finish_cancelled(app, core, controller, &pending).await?;
            return Ok(native_ui_available(app, window));
        };
        Some(token)
    } else {
        None
    };
    if !native_ui_available(app, window) {
        finish_cancelled(app, core, controller, &pending).await?;
        return Ok(false);
    }
    let Ok(result) = controller
        .complete_permission_mode_consent(warning, os_reauthentication)
        .await
    else {
        return Ok(recovery::wait_for_command_terminal(app, core, &pending, None).await);
    };
    if result.code == PermissionControlResultCodeV1::Pending {
        return Ok(recovery::wait_for_command_terminal(app, core, &pending, Some(&result)).await);
    }
    if readback(core, &pending, &result).await.is_ok() {
        return Ok(true);
    }
    Ok(recovery::wait_for_command_terminal(app, core, &pending, Some(&result)).await)
}

fn native_ui_available(app: &AppHandle, window: &WebviewWindow) -> bool {
    !app.try_state::<crate::RuntimeLifecycleManager>()
        .is_some_and(|lifecycle| lifecycle.is_shutting_down())
        && window.is_visible().unwrap_or(false)
}

async fn fresh_os_evidence(
    window: WebviewWindow,
    challenge: runne_api::PermissionControlModeChallengeV1,
) -> Option<permission_reauth_linux::FreshOsReauthentication> {
    let now = unix_millis()?;
    let remaining = challenge.ceremony_expires_at_unix_ms.checked_sub(now)?;
    let bounded = Duration::from_millis(remaining).min(MAX_REAUTH_WINDOW);
    let deadline = Instant::now().checked_add(bounded)?;
    let handler: Arc<dyn PamConversationHandler> = Arc::new(GtkPamHandler::new(window));
    let binding = challenge.issued_challenge_binding_digest;
    tauri::async_runtime::spawn_blocking(move || {
        permission_reauth_linux::reauthenticate(binding, deadline, handler)
    })
    .await
    .ok()?
    .ok()
}

async fn finish_cancelled(
    app: &AppHandle,
    core: &AppCore,
    controller: &BundledRuntimeController,
    pending: &runne_api::PermissionModeNativePendingV2,
) -> Result<(), ()> {
    let Ok(result) = controller.cancel_permission_mode().await else {
        return recovery::wait_for_command_terminal(app, core, pending, None)
            .await
            .then_some(())
            .ok_or(());
    };
    if result.code == PermissionControlResultCodeV1::Pending {
        return recovery::wait_for_command_terminal(app, core, pending, Some(&result))
            .await
            .then_some(())
            .ok_or(());
    }
    if readback(core, pending, &result).await.is_ok() {
        return Ok(());
    }
    recovery::wait_for_command_terminal(app, core, pending, Some(&result))
        .await
        .then_some(())
        .ok_or(())
}

async fn readback(
    core: &AppCore,
    pending: &runne_api::PermissionModeNativePendingV2,
    result: &runne_api::PermissionControlResultV1,
) -> Result<(), ()> {
    let status = core
        .permission_mode_command_status(&pending.workspace_id, &pending.context.command_id)
        .await
        .map_err(|_| ())?;
    readback_matches(result, &status, pending)
        .then_some(())
        .ok_or(())
}

fn readback_matches(
    result: &runne_api::PermissionControlResultV1,
    status: &PermissionModeCommandStatusV2,
    pending: &runne_api::PermissionModeNativePendingV2,
) -> bool {
    let command_id = &pending.context.command_id;
    if uuid::Uuid::from_bytes(result.command_id).to_string() != *command_id
        || result.public_request_digest != pending.context.public_request_digest
    {
        return false;
    }
    match (&result.code, status) {
        (
            PermissionControlResultCodeV1::Committed,
            PermissionModeCommandStatusV2::Committed { receipt },
        ) => {
            command_id_matches(&receipt.command_id, command_id)
                && result.receipt_digest == Some(*receipt.intent_digest.as_bytes())
                && result.authorization_revision == Some(receipt.authorization_revision)
                && result.managed_policy_revision == Some(receipt.history.managed_policy_version)
        }
        (
            PermissionControlResultCodeV1::Pending,
            PermissionModeCommandStatusV2::PendingNativeConfirmation { command_id: id, .. }
            | PermissionModeCommandStatusV2::PendingReauthentication { command_id: id, .. },
        )
        | (
            PermissionControlResultCodeV1::Cancelled,
            PermissionModeCommandStatusV2::Cancelled { command_id: id },
        )
        | (
            PermissionControlResultCodeV1::Expired,
            PermissionModeCommandStatusV2::Expired { command_id: id },
        )
        | (
            PermissionControlResultCodeV1::Invalidated,
            PermissionModeCommandStatusV2::Invalidated { command_id: id },
        ) => command_id_matches(id, command_id),
        _ => false,
    }
}

fn status_belongs_to_pending_command(
    status: &PermissionModeCommandStatusV2,
    pending: &runne_api::PermissionModeNativePendingV2,
) -> bool {
    let expected = &pending.context.command_id;
    match status {
        PermissionModeCommandStatusV2::PendingNativeConfirmation { command_id, .. }
        | PermissionModeCommandStatusV2::PendingReauthentication { command_id, .. }
        | PermissionModeCommandStatusV2::Cancelled { command_id }
        | PermissionModeCommandStatusV2::Expired { command_id }
        | PermissionModeCommandStatusV2::Invalidated { command_id } => {
            command_id_matches(command_id, expected)
        }
        PermissionModeCommandStatusV2::Committed { receipt } => {
            command_id_matches(&receipt.command_id, expected)
        }
    }
}

fn command_id_matches(id: &impl std::fmt::Display, expected: &str) -> bool {
    id.to_string() == expected
}

fn unix_millis() -> Option<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
