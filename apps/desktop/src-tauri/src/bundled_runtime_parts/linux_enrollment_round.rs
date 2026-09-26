use super::{
    AppCoreError, Arc, BUNDLED_CLIENT_CONNECT_TIMEOUT, ConfirmedInstalledNativeEnrollment,
    NativeCredentialEnrollmentLease, ProtectedBundledRuntimeSupervisor,
};

impl NativeCredentialEnrollmentLease {
    pub(crate) async fn rearm_after_terminal_operation(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
    ) -> Result<bool, AppCoreError> {
        let supervisor = Arc::clone(&self.supervisor);
        let terminal = tauri::async_runtime::spawn_blocking(move || {
            supervisor
                .lock()
                .map_err(|_| AppCoreError::RuntimeUnavailable)?
                .linux_credential_enrollment_has_terminal_operation()
                .map_err(|_| AppCoreError::RuntimeUnavailable)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)??;
        if !terminal {
            return Ok(false);
        }

        let result = self.rearm_renewed_terminal_session(confirmed).await;
        if result.is_err() {
            self.cleanup_handle().abort().await;
        }
        result?;
        Ok(true)
    }

    async fn rearm_renewed_terminal_session(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
    ) -> Result<(), AppCoreError> {
        let activation = self.core.begin_bundled_runtime_restart().await?;
        let supervisor = Arc::clone(&self.supervisor);
        tauri::async_runtime::spawn_blocking(move || {
            supervisor
                .lock()
                .map_err(|_| AppCoreError::RuntimeUnavailable)?
                .queue_renewal_profile()
                .map_err(|_| AppCoreError::RuntimeUnavailable)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)??;
        self.install_renewed_profile(activation).await?;
        self.matches_active_signed_linux_v3(confirmed)?;

        let supervisor = Arc::clone(&self.supervisor);
        tauri::async_runtime::spawn_blocking(move || {
            supervisor
                .lock()
                .map_err(|_| AppCoreError::RuntimeUnavailable)?
                .begin_next_linux_protected_credential_round()
                .map_err(|_| AppCoreError::RuntimeUnavailable)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)??;
        Ok(())
    }

    async fn install_renewed_profile(
        &self,
        activation: runne_app_core::BundledRuntimeActivationLease,
    ) -> Result<(), AppCoreError> {
        let supervisor = Arc::clone(&self.supervisor);
        let profile = tauri::async_runtime::spawn_blocking(move || {
            supervisor
                .lock()
                .map_err(|_| AppCoreError::RuntimeUnavailable)?
                .take_runtime_profile()
                .ok_or(AppCoreError::RuntimeUnavailable)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)??;
        let client = profile
            .connect(BUNDLED_CLIENT_CONNECT_TIMEOUT)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let checked = client.clone();
        let supervisor = Arc::clone(&self.supervisor);
        tauri::async_runtime::spawn_blocking(move || {
            supervisor
                .lock()
                .map_err(|_| AppCoreError::RuntimeUnavailable)?
                .record_client_ready(&checked)
                .map_err(|_| AppCoreError::RuntimeUnavailable)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)??;
        self.core
            .install_bundled_runtime_client(activation, client)
            .await
            .map(|_| ())
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }
}
