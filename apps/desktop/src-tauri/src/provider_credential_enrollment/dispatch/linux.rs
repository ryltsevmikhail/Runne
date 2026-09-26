use super::DispatchFailure;
use crate::RuntimeLifecycleManager;
use crate::provider_credential_enrollment::{
    CredentialIntentIpc, CredentialIntentProjection, CredentialIntentRegistry,
};
use crate::updater_status::UpdateStatusStore;
use runne_platform_desktop::SecureCredentialPromptDisposition;
use tauri::{AppHandle, Manager as _, WebviewWindow};

#[path = "linux_exchange.rs"]
mod exchange;

struct EnrollmentLeases {
    runtime: crate::bundled_runtime::NativeCredentialEnrollmentLease,
    updater: crate::updater_status::enrollment::NativeInstalledEnrollmentLease,
}

#[allow(clippy::significant_drop_tightening)]
pub(super) async fn dispatch_inner(
    app: &AppHandle,
    window: WebviewWindow,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
    intents: &CredentialIntentRegistry,
    request: CredentialIntentIpc,
) -> Result<CredentialIntentProjection, DispatchFailure> {
    super::run_after_action_gate(request, || ())?;
    if !request.supported_enrollment_action() {
        return Err(DispatchFailure::Closed(
            "provider_credential_action_unsupported",
        ));
    }

    let mut leases = acquire_enrollment_leases(app, lifecycle, updater).await?;
    let window_label = window.label().to_owned();
    let disposition = show_credential_prompt(request).await?;
    if matches!(disposition, SecureCredentialPromptDisposition::Cancelled) {
        return Ok(CredentialIntentProjection::Cancelled);
    }

    let session = confirm_installed_enrollment(request, &mut leases).await?;
    let (begin, material) =
        exchange::prepare_begin(intents, &window_label, request, session, disposition)?;
    run_fenced_exchange(
        leases,
        begin,
        material,
        request.action == crate::provider_credential_enrollment::CredentialIntentAction::Pair,
    )
    .await
}

async fn acquire_enrollment_leases(
    app: &AppHandle,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
) -> Result<EnrollmentLeases, DispatchFailure> {
    let executable = std::env::current_exe()
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let resources = app
        .path()
        .resource_dir()
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let mut updater = updater
        .prepare_linux_installed_native_enrollment(&executable, &resources)
        .await
        .map_err(|()| DispatchFailure::Closed("provider_credential_unavailable"))?
        .ok_or(DispatchFailure::Closed(
            "provider_credential_enrollment_unavailable",
        ))?;
    updater
        .refresh_linux()
        .map_err(|()| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let runtime = lifecycle
        .acquire_credential_enrollment_lease()
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_runtime_unavailable"))?;
    Ok(EnrollmentLeases { runtime, updater })
}

async fn show_credential_prompt(
    request: CredentialIntentIpc,
) -> Result<SecureCredentialPromptDisposition, DispatchFailure> {
    let prompt_request = request
        .prompt_request()
        .map_err(|()| DispatchFailure::Closed("provider_credential_intent_rejected"))?;
    let mut prompt = super::super::host_prompt::LinuxHostCredentialPrompt::new()
        .map_err(|_| DispatchFailure::Closed("provider_credential_prompt_unavailable"))?;
    tauri::async_runtime::spawn_blocking(move || prompt.prompt(prompt_request))
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_prompt_unavailable"))?
        .map_err(|_| DispatchFailure::Closed("provider_credential_prompt_unavailable"))
}

async fn confirm_installed_enrollment(
    request: CredentialIntentIpc,
    leases: &mut EnrollmentLeases,
) -> Result<[u8; 32], DispatchFailure> {
    crate::provider_credential_enrollment::linux_activation::enforce_pre_prompt_gate(&request)
        .map_err(|_| DispatchFailure::Closed("activation_gate_closed_after_prompt"))?;
    leases
        .updater
        .refresh_linux()
        .map_err(|()| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let prepared = leases
        .updater
        .take_prepared()
        .map_err(|()| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let installed = leases
        .runtime
        .confirm(prepared)
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    leases
        .updater
        .revalidate_confirmed(&installed)
        .map_err(|()| DispatchFailure::Closed("provider_credential_unavailable"))?;
    leases
        .runtime
        .matches_active_signed_linux_v3(&installed)
        .map_err(|_| DispatchFailure::Closed("provider_credential_enrollment_unavailable"))?;
    leases
        .runtime
        .rearm_after_terminal_operation(&installed)
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    leases
        .runtime
        .prepare_credential_status(installed)
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    leases
        .runtime
        .rotated_intent_session_binding()
        .map_err(|_| DispatchFailure::Closed("provider_credential_handoff_failed"))
}

async fn run_fenced_exchange(
    leases: EnrollmentLeases,
    begin: runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin,
    material: Option<runne_platform_desktop::SecureCredentialMaterial>,
    pair: bool,
) -> Result<CredentialIntentProjection, DispatchFailure> {
    let cleanup = leases.runtime.cleanup_handle();
    let supervisor = leases.runtime.supervisor_handle();
    let task = tauri::async_runtime::spawn_blocking(move || {
        let EnrollmentLeases { runtime, updater } = leases;
        let _held_fences = (runtime, updater);
        exchange::run_exchange_owner(&supervisor, begin, material, pair)
    });
    let Ok(result) = task.await else {
        cleanup.abort().await;
        return Err(DispatchFailure::Closed(
            "provider_credential_exchange_failed",
        ));
    };
    if result.is_err() {
        cleanup.abort().await;
        return Err(DispatchFailure::Closed(
            "provider_credential_exchange_failed",
        ));
    }
    Ok(CredentialIntentProjection::Completed)
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
