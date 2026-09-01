use super::{
    AppCoreError, Arc, BUNDLED_CLIENT_CONNECT_TIMEOUT, BundledRuntimeActivationLease,
    ConfirmedInstalledNativeEnrollment, Mutex, NativeCredentialEnrollmentCleanup,
    NativeCredentialEnrollmentLease, PreparedInstalledNativeEnrollment,
    ProtectedBundledRuntimeSupervisor, RuntimeFailureCode, cleanup_after_post_fence_failure,
};

impl NativeCredentialEnrollmentLease {
    pub(crate) fn supervisor_handle(&self) -> Arc<Mutex<ProtectedBundledRuntimeSupervisor>> {
        Arc::clone(&self.supervisor)
    }

    pub(crate) fn cleanup_handle(&self) -> NativeCredentialEnrollmentCleanup {
        NativeCredentialEnrollmentCleanup {
            core: Arc::clone(&self.core),
            supervisor: Arc::clone(&self.supervisor),
        }
    }

    pub(crate) async fn confirm(
        &self,
        prepared: PreparedInstalledNativeEnrollment,
    ) -> Result<ConfirmedInstalledNativeEnrollment, AppCoreError> {
        let supervisor = Arc::clone(&self.supervisor);
        tauri::async_runtime::spawn_blocking(move || {
            supervisor
                .lock()
                .map_err(|_| AppCoreError::RuntimeUnavailable)?
                .confirm_installed_native_enrollment(prepared)
                .map_err(|_| AppCoreError::RuntimeUnavailable)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?
    }

    pub(crate) async fn transition_and_install(
        &self,
        confirmed: ConfirmedInstalledNativeEnrollment,
    ) -> Result<ConfirmedInstalledNativeEnrollment, AppCoreError> {
        let activation = self.core.begin_bundled_runtime_restart().await?;
        match self
            .install_transitioned_profile(activation, confirmed)
            .await
        {
            Ok(confirmed) => Ok(confirmed),
            Err(_) => self.fail_transition().await,
        }
    }

    pub(crate) fn rotated_intent_session_binding(&self) -> Result<[u8; 32], AppCoreError> {
        self.supervisor
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
            .current_credential_enrollment_intent_binding()
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    pub(crate) async fn abort_enrollment(&self) {
        self.cleanup_handle().abort().await;
    }

    pub(crate) fn abort_enrollment_detached(&self) {
        self.cleanup_handle().abort_detached();
    }

    async fn install_transitioned_profile(
        &self,
        activation: BundledRuntimeActivationLease,
        confirmed: ConfirmedInstalledNativeEnrollment,
    ) -> Result<ConfirmedInstalledNativeEnrollment, AppCoreError> {
        let supervisor = Arc::clone(&self.supervisor);
        let confirmed = tauri::async_runtime::spawn_blocking(move || {
            supervisor
                .lock()
                .map_err(|_| AppCoreError::RuntimeUnavailable)?
                .begin_credential_enrollment_transition(&confirmed)
                .map_err(|_| AppCoreError::RuntimeUnavailable)?;
            Ok::<_, AppCoreError>(confirmed)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)??;
        let profile = self
            .supervisor
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
            .take_runtime_profile()
            .ok_or(AppCoreError::RuntimeUnavailable)?;
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
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(confirmed)
    }

    async fn fail_transition<T>(&self) -> Result<T, AppCoreError> {
        self.cleanup_handle().abort().await;
        Err(AppCoreError::RuntimeUnavailable)
    }
}

impl NativeCredentialEnrollmentCleanup {
    pub(crate) async fn abort(&self) {
        let supervisor = Arc::clone(&self.supervisor);
        let stop = async move {
            let _ = tauri::async_runtime::spawn_blocking(move || {
                let _ = supervisor.lock().map(|mut value| value.stop());
            })
            .await;
        };
        let core = Arc::clone(&self.core);
        let degrade = async move {
            let _ = core
                .mark_bundled_runtime_degraded(RuntimeFailureCode::ProtectedActivationUnavailable)
                .await;
        };
        let _ = cleanup_after_post_fence_failure(Err::<(), _>(()), stop, degrade).await;
    }

    fn abort_detached(&self) {
        let _ = self.supervisor.lock().map(|mut value| value.stop());
        let core = Arc::clone(&self.core);
        tauri::async_runtime::spawn(async move {
            let _ = core
                .mark_bundled_runtime_degraded(RuntimeFailureCode::ProtectedActivationUnavailable)
                .await;
        });
    }
}
