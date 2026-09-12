//! Retains native admission fences through the authoritative HTTP status read.

use crate::{AppCore, RuntimeLifecycleManager, UpdateStatusStore};
use runne_api::ProviderCredentialProviderV2;
use runne_app_core::ProviderCredentialEnrollmentProjection;

pub(crate) async fn load_status(
    core: &AppCore,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
    provider: ProviderCredentialProviderV2,
) -> Result<ProviderCredentialEnrollmentProjection, ()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
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
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (core, lifecycle, updater, provider);
        Err(())
    }
}
