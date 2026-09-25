impl BundledRuntimeController {
    async fn monitor_loop(self: Arc<Self>, app: tauri::AppHandle) {
        let mut interval = tokio::time::interval(SUPERVISOR_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if self.operation_fence.is_stopping() {
                break;
            }
            Box::pin(self.monitor_once(|| async {
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                {
                    use tauri::Manager;
                    let lifecycle = app.state::<crate::RuntimeLifecycleManager>();
                    let updates = app.state::<crate::UpdateStatusStore>();
                    if crate::provider_credential_enrollment::reconcile_startup(
                        &lifecycle, &updates,
                    )
                    .await
                    .is_err()
                    {
                        let _ = self
                            .core
                            .mark_bundled_runtime_degraded(
                                RuntimeFailureCode::ProtectedActivationUnavailable,
                            )
                            .await;
                    }
                }
                #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                let _ = &app;
            }))
            .await;
        }
    }

    async fn monitor_once<F: Future<Output = ()>>(&self, cleanup: impl FnOnce() -> F) {
        let Some(operation) = self.operation_fence.enter().await else {
            return;
        };
        let Ok(before) = self.supervisor_state() else {
            let _ = self
                .core
                .mark_bundled_runtime_failed(RuntimeFailureCode::ProtectedActivationUnavailable)
                .await;
            return;
        };
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if let Err(error) = self.drive_credential_service_rejoin().await {
            let _ = self
                .reject_current_client(map_protected_failure(error))
                .await;
            return;
        }
        let monitor_result = self
            .run_supervisor(ProtectedBundledRuntimeSupervisor::monitor)
            .await;
        let Ok(after) = self.supervisor_state() else {
            let _ = self
                .core
                .mark_bundled_runtime_failed(RuntimeFailureCode::ProtectedActivationUnavailable)
                .await;
            return;
        };

        if let Err(error) = monitor_result {
            let failure = map_protected_failure(error);
            if after == BundledRuntimeLifecycleState::Exhausted {
                let _ = self.core.mark_bundled_runtime_failed(failure).await;
            } else {
                let _ = self.core.mark_bundled_runtime_degraded(failure).await;
            }
            return;
        }

        match (before, after) {
            (BundledRuntimeLifecycleState::Ready, BundledRuntimeLifecycleState::Ready)
                if self.renewal_is_due().unwrap_or(true) =>
            {
                Box::pin(self.rotate_protected_session()).await;
            }
            (
                BundledRuntimeLifecycleState::Ready | BundledRuntimeLifecycleState::Handshaking,
                BundledRuntimeLifecycleState::Backoff,
            ) => {
                let _ = self.clear_renewal_schedule();
                let _ = self.core.begin_bundled_runtime_restart().await;
            }
            (BundledRuntimeLifecycleState::Backoff, BundledRuntimeLifecycleState::Handshaking) => {
                let Ok(lease) = self.core.begin_bundled_runtime_restart().await else {
                    return;
                };
                let availability = Box::pin(self.connect_pending_profile(lease, true)).await;
                restart_cleanup::complete_monitor_restart(availability, operation, cleanup).await;
            }
            (_, BundledRuntimeLifecycleState::Exhausted) => {
                let _ = self
                    .core
                    .mark_bundled_runtime_failed(RuntimeFailureCode::BundledRestartExhausted)
                    .await;
            }
            _ => {}
        }
    }

    async fn rotate_protected_session(&self) {
        self.clear_renewal_schedule().ok();
        let Ok(lease) = self.core.begin_bundled_runtime_restart().await else {
            return;
        };
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let renewal = ProtectedBundledRuntimeSupervisor::queue_renewal_profile_with_rejoin(
            Arc::clone(&self.supervisor),
        )
        .await;
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let renewal = self
            .run_supervisor(ProtectedBundledRuntimeSupervisor::queue_renewal_profile)
            .await;
        if let Err(error) = renewal {
            let _ = self
                .reject_current_client(map_protected_failure(error))
                .await;
            return;
        }
        let _ = Box::pin(self.connect_pending_profile(lease, false)).await;
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    async fn drive_credential_service_rejoin(&self) -> Result<(), ProtectedBundledRuntimeError> {
        let prepared = self
            .run_supervisor(|supervisor| supervisor.prepare_pending_credential_service_rejoin())
            .await?;
        let Some(prepared) = prepared else {
            return Ok(());
        };
        let registered = prepared.register().await?;
        self.run_supervisor(move |supervisor| {
            supervisor.confirm_credential_service_rejoin(registered)
        })
        .await
    }

    fn arm_renewal_schedule(&self) -> Result<(), AppCoreError> {
        self.renewal_schedule
            .lock()
            .map(|mut schedule| schedule.arm(Instant::now()))
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn clear_renewal_schedule(&self) -> Result<(), AppCoreError> {
        self.renewal_schedule
            .lock()
            .map(|mut schedule| schedule.clear())
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn renewal_is_due(&self) -> Result<bool, AppCoreError> {
        self.renewal_schedule
            .lock()
            .map(|schedule| schedule.is_due(Instant::now()))
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn supervisor_state(&self) -> Result<BundledRuntimeLifecycleState, AppCoreError> {
        self.supervisor
            .lock()
            .map(|supervisor| supervisor.state())
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    async fn run_supervisor<T, F>(&self, action: F) -> Result<T, ProtectedBundledRuntimeError>
    where
        T: Send + 'static,
        F: FnOnce(
                &mut ProtectedBundledRuntimeSupervisor,
            ) -> Result<T, ProtectedBundledRuntimeError>
            + Send
            + 'static,
    {
        let supervisor = Arc::clone(&self.supervisor);
        tokio::task::spawn_blocking(move || {
            let mut supervisor = supervisor
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            action(&mut supervisor)
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?
    }
}

#[cfg(target_os = "linux")]
impl BundledRuntimeController {
    #[rustfmt::skip]
    async fn prepare_linux_startup(&self) -> Result<Option<crate::updater_status::enrollment::NativeInstalledEnrollmentLease>, AppCoreError> {
        use tauri::Manager as _;
        let app = self.startup_app.lock().map_err(|_| AppCoreError::RuntimeUnavailable)?.clone().ok_or(AppCoreError::RuntimeUnavailable)?;
        let executable = std::env::current_exe().map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let resources = app.path().resource_dir().map_err(|_| AppCoreError::RuntimeUnavailable)?;
        app.state::<crate::updater_status::UpdateStatusStore>()
            .prepare_startup_linux_native_enrollment(&executable, &resources)
            .await
            .map_err(|()| AppCoreError::RuntimeUnavailable)
    }
}

#[cfg(target_os = "linux")]
impl NativeCredentialEnrollmentLease {
    #[rustfmt::skip]
    pub(crate) async fn confirm(
        &self,
        prepared: PreparedInstalledNativeEnrollment,
    ) -> Result<ConfirmedInstalledNativeEnrollment, AppCoreError> {
        let supervisor = Arc::clone(&self.supervisor);
        tauri::async_runtime::spawn_blocking(move || supervisor.lock().map_err(|_| AppCoreError::RuntimeUnavailable)?.confirm_installed_native_enrollment(prepared).map_err(|_| AppCoreError::RuntimeUnavailable)).await.map_err(|_| AppCoreError::RuntimeUnavailable)?
    }

    #[rustfmt::skip]
    pub(crate) async fn prepare_credential_status(
        &self,
        confirmed: ConfirmedInstalledNativeEnrollment,
    ) -> Result<(), AppCoreError> {
        let supervisor = Arc::clone(&self.supervisor);
        tauri::async_runtime::spawn_blocking(move || supervisor.lock().map_err(|_| AppCoreError::RuntimeUnavailable)?.prepare_credential_status(&confirmed).map_err(|_| AppCoreError::RuntimeUnavailable)).await.map_err(|_| AppCoreError::RuntimeUnavailable)?
    }

    pub(crate) fn supervisor_handle(&self) -> Arc<Mutex<ProtectedBundledRuntimeSupervisor>> {
        Arc::clone(&self.supervisor)
    }

    pub(crate) fn writer_reaper_registry(&self) -> Arc<ProtectedWriterReaperRegistry> {
        Arc::clone(&self.writer_reapers)
    }

    pub(crate) fn cleanup_handle(&self) -> NativeCredentialEnrollmentCleanup {
        NativeCredentialEnrollmentCleanup {
            core: Arc::clone(&self.core),
            supervisor: Arc::clone(&self.supervisor),
            writer_reapers: Arc::clone(&self.writer_reapers),
        }
    }

    pub(crate) fn rotated_intent_session_binding(&self) -> Result<[u8; 32], AppCoreError> {
        self.supervisor
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
            .current_credential_enrollment_intent_binding()
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    pub(crate) fn matches_active_signed_linux_v3(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
    ) -> Result<(), AppCoreError> {
        let marker = self
            .active_signed_linux_v3
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        marker
            .as_ref()
            .is_some_and(|marker| marker.matches(confirmed))
            .then_some(())
            .ok_or(AppCoreError::RuntimeUnavailable)
    }
}
