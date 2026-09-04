use super::{
    AppCoreError, Arc, BUNDLED_CLIENT_CONNECT_TIMEOUT, BundledRuntimeActivationLease,
    ConfirmedInstalledNativeEnrollment, Mutex, NativeCredentialEnrollmentCleanup,
    NativeCredentialEnrollmentLease, PreparedInstalledNativeEnrollment,
    ProtectedBundledRuntimeSupervisor, ProtectedWriterReaperRegistry, RuntimeFailureCode,
};
#[cfg(test)]
use super::{CredentialWriterReaperSnapshot, WRITER_REAPER_POLL_INTERVAL};

impl NativeCredentialEnrollmentLease {
    pub(crate) fn supervisor_handle(&self) -> Arc<Mutex<ProtectedBundledRuntimeSupervisor>> {
        Arc::clone(&self.supervisor)
    }

    pub(crate) fn cleanup_handle(&self) -> NativeCredentialEnrollmentCleanup {
        NativeCredentialEnrollmentCleanup {
            core: Arc::clone(&self.core),
            supervisor: Arc::clone(&self.supervisor),
            writer_reapers: Arc::clone(&self.writer_reapers),
        }
    }

    pub(crate) fn writer_reaper_registry(&self) -> Arc<ProtectedWriterReaperRegistry> {
        Arc::clone(&self.writer_reapers)
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

    pub(crate) async fn renew_and_install(&self) -> Result<(), AppCoreError> {
        let activation = self.core.begin_bundled_runtime_restart().await?;
        ProtectedBundledRuntimeSupervisor::queue_renewal_profile_with_rejoin(Arc::clone(
            &self.supervisor,
        ))
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        self.install_pending_profile(activation).await
    }

    pub(crate) fn rotated_intent_session_binding(&self) -> Result<[u8; 32], AppCoreError> {
        self.supervisor
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
            .current_credential_enrollment_intent_binding()
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    pub(crate) async fn register_credential_service_session(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
    ) -> Result<(), AppCoreError> {
        let prepared = self
            .supervisor
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
            .prepare_credential_service_session_registration(confirmed)
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let registered = prepared
            .register()
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        self.supervisor
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
            .confirm_credential_service_session(registered)
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
        self.install_pending_profile(activation).await?;
        Ok(confirmed)
    }

    async fn install_pending_profile(
        &self,
        activation: BundledRuntimeActivationLease,
    ) -> Result<(), AppCoreError> {
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
        Ok(())
    }
}

impl NativeCredentialEnrollmentCleanup {
    pub(crate) async fn abort(&self) {
        self.clone().stop_and_degrade().await;
    }

    async fn stop_and_degrade(self) {
        let supervisor = Arc::clone(&self.supervisor);
        let _ = tauri::async_runtime::spawn_blocking(move || {
            let mut value = supervisor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = value.stop();
        })
        .await;
        let _ = self
            .core
            .mark_bundled_runtime_degraded(RuntimeFailureCode::ProtectedActivationUnavailable)
            .await;
        let reapers = Arc::clone(&self.writer_reapers);
        let _ = tauri::async_runtime::spawn_blocking(move || reapers.retry_all_after_outer_stop())
            .await;
    }

    #[cfg(test)]
    pub(crate) fn writer_reaper_registry(&self) -> Arc<ProtectedWriterReaperRegistry> {
        Arc::clone(&self.writer_reapers)
    }
}

#[cfg(test)]
pub struct TestOnlyLiveEnrollmentRuntime {
    operation_fence: Arc<tokio::sync::Mutex<()>>,
    lease: Option<NativeCredentialEnrollmentLease>,
    core: Arc<runne_app_core::AppCore>,
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    writer_reapers: Arc<ProtectedWriterReaperRegistry>,
}

#[cfg(test)]
impl TestOnlyLiveEnrollmentRuntime {
    pub(crate) fn operation_available(&self) -> bool {
        self.operation_fence.try_lock().is_ok()
    }
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
        let stopped = self
            .supervisor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stopped = {
            matches!(
                stopped.state(),
                runne_platform_desktop::BundledRuntimeLifecycleState::Stopped
                    | runne_platform_desktop::BundledRuntimeLifecycleState::FailedStart
            )
        };
        let degraded = self.core.bootstrap().is_ok_and(|value| {
            value.runtime_failure == Some(RuntimeFailureCode::ProtectedActivationUnavailable)
        });
        stopped && degraded
    }

    pub(crate) fn supervisor_handle(&self) -> Arc<Mutex<ProtectedBundledRuntimeSupervisor>> {
        Arc::clone(&self.supervisor)
    }

    pub(crate) fn writer_reaper_snapshot(&self) -> Vec<CredentialWriterReaperSnapshot> {
        self.writer_reapers.snapshot()
    }

    pub(crate) fn writer_reaper_registry(&self) -> Arc<ProtectedWriterReaperRegistry> {
        Arc::clone(&self.writer_reapers)
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
    let writer_reapers = ProtectedWriterReaperRegistry::start(WRITER_REAPER_POLL_INTERVAL)
        .expect("test writer reaper registry");
    let operation_fence = Arc::new(tokio::sync::Mutex::new(()));
    let operation = Arc::clone(&operation_fence).lock_owned().await;
    TestOnlyLiveEnrollmentRuntime {
        operation_fence,
        lease: Some(NativeCredentialEnrollmentLease {
            core: Arc::clone(&core),
            supervisor: Arc::clone(&supervisor),
            writer_reapers: Arc::clone(&writer_reapers),
            operation_permit: operation,
        }),
        core,
        supervisor,
        writer_reapers,
    }
}
