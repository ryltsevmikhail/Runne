use super::{
    AppCoreError, Arc, BUNDLED_CLIENT_CONNECT_TIMEOUT, BundledRuntimeActivationLease,
    ConfirmedInstalledNativeEnrollment, Mutex, NativeCredentialEnrollmentCleanup,
    NativeCredentialEnrollmentLease, PreparedInstalledNativeEnrollment,
    ProtectedBundledRuntimeSupervisor, RuntimeFailureCode,
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
        self.install_transitioned_profile(activation, confirmed)
            .await
    }

    pub(crate) fn rotated_intent_session_binding(&self) -> Result<[u8; 32], AppCoreError> {
        self.supervisor
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
            .current_credential_enrollment_intent_binding()
            .map_err(|_| AppCoreError::RuntimeUnavailable)
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
}

impl NativeCredentialEnrollmentCleanup {
    pub(crate) async fn abort(&self) {
        self.clone().stop_and_degrade().await;
    }

    async fn stop_and_degrade(self) {
        let supervisor = Arc::clone(&self.supervisor);
        let _ = tauri::async_runtime::spawn_blocking(move || {
            let _ = supervisor.lock().map(|mut value| value.stop());
        })
        .await;
        let _ = self
            .core
            .mark_bundled_runtime_degraded(RuntimeFailureCode::ProtectedActivationUnavailable)
            .await;
    }
}

#[cfg(test)]
pub struct TestOnlyLiveEnrollmentRuntime {
    lease: Option<NativeCredentialEnrollmentLease>,
    core: Arc<runne_app_core::AppCore>,
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
}

#[cfg(test)]
impl TestOnlyLiveEnrollmentRuntime {
    pub(crate) fn take_lease_with_cleanup(
        &mut self,
    ) -> (
        NativeCredentialEnrollmentLease,
        NativeCredentialEnrollmentCleanup,
    ) {
        let lease = self.lease.take().expect("test enrollment lease");
        let cleanup = lease.cleanup_handle();
        (lease, cleanup)
    }

    pub(crate) fn cleanup_completed(&self) -> bool {
        let stopped = self.supervisor.lock().is_ok_and(|value| {
            matches!(
                value.state(),
                runne_platform_desktop::BundledRuntimeLifecycleState::Stopped
                    | runne_platform_desktop::BundledRuntimeLifecycleState::FailedStart
            )
        });
        let degraded = self.core.bootstrap().is_ok_and(|value| {
            value.runtime_failure == Some(RuntimeFailureCode::ProtectedActivationUnavailable)
        });
        stopped && degraded
    }
}

#[cfg(test)]
pub async fn test_only_live_enrollment_runtime(
    directory: &std::path::Path,
    fixture: runne_platform_desktop::TestOnlyReadyV3EnrollmentSupervisor,
) -> TestOnlyLiveEnrollmentRuntime {
    let core = Arc::new(
        runne_app_core::AppCore::open_with_runtime_mode(
            &directory.join("profile.sqlite3"),
            runne_app_core::RuntimeMode::Bundled,
        )
        .expect("test AppCore"),
    );
    let supervisor = Arc::new(Mutex::new(fixture.into_supervisor()));
    let operation = Arc::new(tokio::sync::Mutex::new(())).lock_owned().await;
    TestOnlyLiveEnrollmentRuntime {
        lease: Some(NativeCredentialEnrollmentLease {
            core: Arc::clone(&core),
            supervisor: Arc::clone(&supervisor),
            operation_permit: operation,
        }),
        core,
        supervisor,
    }
}
