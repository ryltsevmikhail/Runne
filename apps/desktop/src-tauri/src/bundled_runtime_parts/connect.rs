impl BundledRuntimeController {
    /// Builds the production protected bundled-runtime supervisor.
    ///
    /// # Errors
    ///
    /// Returns one closed renderer-safe configuration code. No external
    /// runtime fallback is attempted.
    pub fn discover(
        core: Arc<AppCore>,
        desktop_executable: &std::path::Path,
        runtime_root: &std::path::Path,
    ) -> Result<Arc<Self>, RuntimeFailureCode> {
        let executable =
            discover_bundled_runtime(desktop_executable).map_err(map_protected_failure)?;
        let spec = ProtectedBundledRuntimeLaunchSpec::new(&executable, runtime_root)
            .map_err(map_protected_failure)?
            .with_openai_provider_activation();
        let supervisor =
            ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
        let writer_reapers = ProtectedWriterReaperRegistry::start(WRITER_REAPER_POLL_INTERVAL)
            .map_err(|_| RuntimeFailureCode::ProtectedActivationUnavailable)?;
        Ok(Arc::new(Self {
            core,
            supervisor: Arc::new(Mutex::new(supervisor)),
            operation_fence: Arc::new(RuntimeOperationFence::new()),
            renewal_schedule: Mutex::new(ProtectedSessionRenewalSchedule::new(
                PROTECTED_BUNDLED_SESSION_RENEW_AFTER,
            )),
            shutdown_outcome: Mutex::new(None),
            writer_reapers,
            startup_app: Mutex::new(None),
            #[cfg(target_os = "linux")]
            active_signed_linux_v3: Arc::new(Mutex::new(None)),
        }))
    }

    /// Starts the loopback fixture through an explicit native-only test gate.
    ///
    /// This API is absent from production builds and is not evidence that a
    /// native credential enrollment has been completed.
    ///
    /// # Errors
    ///
    /// Returns one closed renderer-safe code when the controlled fixture
    /// executable or its owner-private runtime root is rejected.
    #[cfg(feature = "test-support")]
    pub fn discover_with_loopback_openai_activation(
        core: Arc<AppCore>,
        desktop_executable: &std::path::Path,
        runtime_root: &std::path::Path,
        _gate: NativeOpenAiActivationTestGate,
    ) -> Result<Arc<Self>, RuntimeFailureCode> {
        let executable =
            discover_bundled_runtime(desktop_executable).map_err(map_protected_failure)?;
        let spec = ProtectedBundledRuntimeLaunchSpec::new(&executable, runtime_root)
            .map_err(map_protected_failure)?
            .with_openai_provider_activation();
        let supervisor =
            ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
        let writer_reapers = ProtectedWriterReaperRegistry::start(WRITER_REAPER_POLL_INTERVAL)
            .map_err(|_| RuntimeFailureCode::ProtectedActivationUnavailable)?;
        Ok(Arc::new(Self {
            core,
            supervisor: Arc::new(Mutex::new(supervisor)),
            operation_fence: Arc::new(RuntimeOperationFence::new()),
            renewal_schedule: Mutex::new(ProtectedSessionRenewalSchedule::new(
                PROTECTED_BUNDLED_SESSION_RENEW_AFTER,
            )),
            shutdown_outcome: Mutex::new(None),
            writer_reapers,
            startup_app: Mutex::new(None),
            #[cfg(target_os = "linux")]
            active_signed_linux_v3: Arc::new(Mutex::new(None)),
        }))
    }

    /// Starts the bounded monitor on the native async runtime.
    pub fn spawn_monitor(self: &Arc<Self>, app: tauri::AppHandle) {
        if let Ok(mut startup_app) = self.startup_app.lock() {
            *startup_app = Some(app.clone());
        }
        let controller = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            controller.monitor_loop(app).await;
        });
    }

    #[must_use]
    pub fn shutdown_outcome(&self) -> Option<BundledShutdownOutcome> {
        self.shutdown_outcome
            .lock()
            .map_or(Some(BundledShutdownOutcome::Incomplete), |outcome| *outcome)
    }

    #[must_use]
    pub fn credential_writer_reaper_snapshot(&self) -> Vec<CredentialWriterReaperSnapshot> {
        self.writer_reapers.snapshot()
    }

    async fn connect(&self) -> Result<RuntimeAvailability, AppCoreError> {
        let Some(_operation) = self.operation_fence.enter().await else {
            return Err(AppCoreError::RuntimeUnavailable);
        };
        match self.supervisor_state()? {
            BundledRuntimeLifecycleState::Absent => self.start_fresh(false).await,
            BundledRuntimeLifecycleState::Stopped
            | BundledRuntimeLifecycleState::FailedStart
            | BundledRuntimeLifecycleState::Exhausted => self.start_fresh(true).await,
            BundledRuntimeLifecycleState::Ready => {
                let availability = self.core.bootstrap()?.runtime;
                if matches!(
                    availability,
                    RuntimeAvailability::Live | RuntimeAvailability::ResyncRequired
                ) {
                    Ok(availability)
                } else {
                    Err(AppCoreError::RuntimeUnavailable)
                }
            }
            BundledRuntimeLifecycleState::Handshaking
            | BundledRuntimeLifecycleState::Backoff
            | BundledRuntimeLifecycleState::ValidatingBinary
            | BundledRuntimeLifecycleState::Spawning
            | BundledRuntimeLifecycleState::Disconnected
            | BundledRuntimeLifecycleState::Probing
            | BundledRuntimeLifecycleState::Crashed
            | BundledRuntimeLifecycleState::Stopping
            | BundledRuntimeLifecycleState::Incompatible
            | BundledRuntimeLifecycleState::IdentityMismatch
            | BundledRuntimeLifecycleState::OwnershipConflict => {
                Err(AppCoreError::RuntimeUnavailable)
            }
        }
    }

    async fn start_fresh(&self, restarting: bool) -> Result<RuntimeAvailability, AppCoreError> {
        self.clear_renewal_schedule()?;
        #[cfg(target_os = "linux")]
        self.clear_linux_enrollment_marker()?;
        let lease = if restarting {
            self.core.begin_bundled_runtime_restart().await?
        } else {
            self.core.begin_bundled_runtime_start().await?
        };
        if let Err(error) = self
            .run_supervisor(ProtectedBundledRuntimeSupervisor::start)
            .await
        {
            self.core
                .mark_bundled_runtime_failed(map_protected_failure(error))
                .await?;
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.connect_pending_profile(lease, true).await
    }

    async fn connect_pending_profile(
        &self,
        lease: BundledRuntimeActivationLease,
        transition_required: bool,
    ) -> Result<RuntimeAvailability, AppCoreError> {
        #[cfg(target_os = "linux")]
        if transition_required {
            self.clear_linux_enrollment_marker()?;
        }
        #[cfg(target_os = "linux")]
        let mut installed = match self.prepare_linux_startup(transition_required).await {
            Ok(installed) => installed,
            Err(_) => return self.reject_linux_startup().await,
        };
        #[cfg(target_os = "linux")]
        let previous_marker = self
            .active_signed_linux_v3
            .lock()
            .ok()
            .and_then(|marker| *marker);
        #[cfg(target_os = "linux")]
        if installed.is_none() && transition_required {
            if let Err(error) = self
                .run_supervisor(
                    ProtectedBundledRuntimeSupervisor::begin_local_linux_enrollment_transition,
                )
                .await
            {
                return self
                    .reject_current_client(map_protected_failure(error))
                    .await;
            }
        }
        let profile = self
            .supervisor
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)?
            .take_runtime_profile();
        let Some(profile) = profile else {
            self.core
                .mark_bundled_runtime_failed(RuntimeFailureCode::ProtectedActivationUnavailable)
                .await?;
            return Err(AppCoreError::RuntimeUnavailable);
        };
        let Ok(client) = profile.connect(BUNDLED_CLIENT_CONNECT_TIMEOUT).await else {
            return self
                .reject_current_client(RuntimeFailureCode::ProtectedReadinessRejected)
                .await;
        };
        let checked_client = client.clone();
        if let Err(error) = self
            .run_supervisor(move |supervisor| supervisor.record_client_ready(&checked_client))
            .await
        {
            return self
                .reject_current_client(map_protected_failure(error))
                .await;
        }
        if self.operation_fence.is_stopping() {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.arm_renewal_schedule()?;
        if self
            .core
            .install_bundled_runtime_client(lease, client)
            .await
            .is_err()
        {
            return self
                .reject_current_client(RuntimeFailureCode::ProtectedReadinessRejected)
                .await;
        }
        #[cfg(target_os = "linux")]
        if let Some(installed) = installed.as_mut() {
            if self
                .confirm_linux_marker(installed, transition_required, previous_marker)
                .await
                .is_err()
            {
                return self.reject_linux_startup().await;
            }
        } else if !transition_required {
            self.clear_linux_enrollment_marker()?;
        }
        Ok(RuntimeAvailability::Live)
    }

    #[cfg(target_os = "linux")]
    #[rustfmt::skip]
    async fn confirm_linux_marker(&self, installed: &mut crate::updater_status::enrollment::NativeInstalledEnrollmentLease,
        transition_required: bool, previous: Option<crate::bundled_runtime::ActiveSignedLinuxV3Marker>) -> Result<(), AppCoreError> {
        installed.refresh_linux().map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let prepared = installed.take_prepared().map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let current = self.run_supervisor(move |s| s.confirm_installed_native_enrollment(prepared)).await.map_err(|_| AppCoreError::RuntimeUnavailable)?;
        installed.revalidate_confirmed(&current).map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let marker = crate::bundled_runtime::ActiveSignedLinuxV3Marker::from_confirmed(&current).ok_or(AppCoreError::RuntimeUnavailable)?;
        if !transition_required && previous.is_some_and(|value| value != marker) { return Err(AppCoreError::RuntimeUnavailable); }
        if transition_required || previous.is_some() { *self.active_signed_linux_v3.lock().map_err(|_| AppCoreError::RuntimeUnavailable)? = Some(marker); }
        Ok(())
    }

    async fn reject_current_client(
        &self,
        failure: RuntimeFailureCode,
    ) -> Result<RuntimeAvailability, AppCoreError> {
        #[cfg(target_os = "linux")]
        self.clear_linux_enrollment_marker()?;
        self.clear_renewal_schedule()?;
        let supervisor_result = self
            .run_supervisor(ProtectedBundledRuntimeSupervisor::record_client_failure)
            .await;
        let failure = supervisor_result
            .err()
            .map_or(failure, map_protected_failure);
        let terminal = matches!(
            failure,
            RuntimeFailureCode::BundledRestartExhausted
                | RuntimeFailureCode::BundledShutdownIncomplete
                | RuntimeFailureCode::UnsupportedPlatformBackend
        );
        if terminal {
            self.core.mark_bundled_runtime_failed(failure).await?;
        } else {
            self.core.mark_bundled_runtime_degraded(failure).await?;
        }
        Err(AppCoreError::RuntimeUnavailable)
    }

    #[cfg(target_os = "linux")]
    async fn reject_linux_startup(&self) -> Result<RuntimeAvailability, AppCoreError> {
        self.reject_current_client(RuntimeFailureCode::ProtectedActivationUnavailable)
            .await
    }
}
