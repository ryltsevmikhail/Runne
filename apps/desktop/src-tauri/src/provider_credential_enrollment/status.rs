//! Retains native admission fences through the authoritative HTTP status read.

use crate::{AppCore, RuntimeLifecycleManager, UpdateStatusStore};
use runne_api::ProviderCredentialProviderV2;
use runne_app_core::ProviderCredentialEnrollmentProjection;

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
        use tauri::Manager as _;

        // Keep the installed updater operation and runtime lease through the
        // authoritative HTTP read, matching Linux enrollment dispatch.
        let executable = std::env::current_exe().map_err(|_| ())?;
        let resources = app.path().resource_dir().map_err(|_| ())?;
        let mut installed = updater
            .prepare_linux_installed_native_enrollment(&executable, &resources)
            .await?
            .ok_or(())?;
        installed.refresh_linux()?;
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
            .matches_active_signed_linux_v3(&confirmed)
            .map_err(|_| ())?;
        runtime
            .prepare_credential_status(confirmed)
            .await
            .map_err(|_| ())?;
        core.provider_credential_enrollment_status(provider)
            .await
            .map_err(|_| ())
    }
    #[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
    {
        let _ = (app, core, lifecycle, updater, provider);
        Err(())
    }
}
