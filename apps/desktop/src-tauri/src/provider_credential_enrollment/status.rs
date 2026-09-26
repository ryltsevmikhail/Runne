//! Retains native admission fences through the authoritative HTTP status read.

use crate::{AppCore, RuntimeLifecycleManager, UpdateStatusStore};
use runne_api::ProviderCredentialProviderV2;
use runne_app_core::ProviderCredentialEnrollmentProjection;

#[cfg(target_os = "linux")]
fn linux_status_diagnostic(stage: &'static str) {
    eprintln!("linux-credential-status stage={stage}");
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "retain the admitted installation and runtime lease through the authoritative status read"
)]
pub async fn load_status(
    app: &tauri::AppHandle,
    core: &AppCore,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
    provider: ProviderCredentialProviderV2,
) -> Result<ProviderCredentialEnrollmentProjection, ()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let _ = app;
        // Match enrollment's lock order; neither renewal nor update may replace
        // the admitted installation between the prelude and the HTTP read.
        let mut installed = updater
            .prepare_installed_native_enrollment()
            .await?
            .ok_or(())?;
        let runtime = lifecycle
            .acquire_credential_enrollment_lease()
            .await
            .map_err(|_| ())?;
        let confirmed = runtime
            .confirm(installed.take_prepared()?)
            .await
            .map_err(|_| ())?;
        installed.revalidate_confirmed(&confirmed)?;
        runtime
            .prepare_credential_status(confirmed)
            .await
            .map_err(|_| ())?;
        core.provider_credential_enrollment_status(provider)
            .await
            .map_err(|_| ())
    }
    #[cfg(target_os = "linux")]
    {
        load_linux_status(app, core, lifecycle, updater, provider).await
    }
    #[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
    {
        let _ = (app, core, lifecycle, updater, provider);
        Err(())
    }
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::significant_drop_tightening,
    reason = "retain the admitted installation and runtime lease through the authoritative status read"
)]
async fn load_linux_status(
    app: &tauri::AppHandle,
    core: &AppCore,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
    provider: ProviderCredentialProviderV2,
) -> Result<ProviderCredentialEnrollmentProjection, ()> {
    use tauri::Manager as _;

    // Retain installation admission and runtime lease through the HTTP read.
    let executable = std::env::current_exe().map_err(|_| {
        linux_status_diagnostic("executable_path");
    })?;
    let resources = app.path().resource_dir().map_err(|_| {
        linux_status_diagnostic("resource_directory");
    })?;
    let mut installed = updater
        .prepare_linux_installed_native_enrollment(&executable, &resources)
        .await
        .map_err(|()| linux_status_diagnostic("installed_enrollment_prepare"))?
        .ok_or_else(|| linux_status_diagnostic("installed_enrollment_unavailable"))?;
    installed
        .refresh_linux()
        .map_err(|()| linux_status_diagnostic("installed_enrollment_refresh"))?;
    let runtime = lifecycle
        .acquire_credential_enrollment_lease()
        .await
        .map_err(|_| linux_status_diagnostic("runtime_lease"))?;
    let prepared = installed
        .take_prepared()
        .map_err(|()| linux_status_diagnostic("prepared_installation"))?;
    let confirmed = runtime
        .confirm(prepared)
        .await
        .map_err(|_| linux_status_diagnostic("runtime_confirmation"))?;
    installed
        .revalidate_confirmed(&confirmed)
        .map_err(|()| linux_status_diagnostic("confirmed_installation_revalidation"))?;
    runtime
        .matches_active_signed_linux_v3(&confirmed)
        .map_err(|_| linux_status_diagnostic("active_signed_v3_marker"))?;
    runtime
        .prepare_credential_status(confirmed)
        .await
        .map_err(|_| linux_status_diagnostic("credential_status_preparation"))?;
    core.provider_credential_enrollment_status(provider)
        .await
        .map_err(|_| linux_status_diagnostic("http_status_projection"))
}
