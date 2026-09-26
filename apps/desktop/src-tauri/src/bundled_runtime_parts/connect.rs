impl BundledRuntimeController {
    /// Builds the production protected bundled-runtime supervisor.
    /// # Errors
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
        #[cfg(target_os = "linux")]
        let signed_linux_v3_latch_path = linux_v3_latch::state_path(spec.runtime_root())
            .map_err(|_| RuntimeFailureCode::ProtectedActivationUnavailable)?;
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
            #[cfg(target_os = "linux")]
            signed_linux_v3_latch_path,
        }))
    }

    /// Starts the loopback fixture through an explicit native-only test gate.
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
        #[cfg(target_os = "linux")]
        let signed_linux_v3_latch_path = linux_v3_latch::state_path(spec.runtime_root())
            .map_err(|_| RuntimeFailureCode::ProtectedActivationUnavailable)?;
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
            #[cfg(target_os = "linux")]
            signed_linux_v3_latch_path,
        }))
    }

    /// Starts the bounded monitor on the native async runtime.
    pub fn spawn_monitor(self: &Arc<Self>, app: tauri::AppHandle) {
        if let Ok(mut startup_app) = self.startup_app.lock() {
            *startup_app = Some(app.clone());
        }
        let controller = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            Box::pin(controller.monitor_loop(app)).await;
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
            BundledRuntimeLifecycleState::Absent => Box::pin(self.start_fresh(false)).await,
            BundledRuntimeLifecycleState::Stopped
            | BundledRuntimeLifecycleState::FailedStart
            | BundledRuntimeLifecycleState::Exhausted => Box::pin(self.start_fresh(true)).await,
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
        Box::pin(self.connect_pending_profile(lease, true)).await
    }

    async fn connect_pending_profile(
        &self,
        lease: BundledRuntimeActivationLease,
        _transition_required: bool,
    ) -> Result<RuntimeAvailability, AppCoreError> {
        #[cfg(target_os = "linux")]
        let previous_marker = self
            .active_signed_linux_v3
            .lock()
            .map_err(|_| AppCoreError::RuntimeUnavailable)
            .map(|marker| *marker)?;
        #[cfg(target_os = "linux")]
        let Ok(signed_v3_was_active) = linux_v3_latch::load(&self.signed_linux_v3_latch_path) else {
            return self.reject_linux_startup_at("latch_load").await;
        };
        #[cfg(target_os = "linux")]
        let Ok(mut installed) = self.prepare_linux_startup().await else {
            return self.reject_linux_startup_at("installed_preparation").await;
        };
        #[cfg(target_os = "linux")]
        let pending_profile_is_v3 = self
            .run_supervisor(|supervisor| supervisor.pending_profile_is_v3())
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        #[cfg(target_os = "linux")]
        match linux_signed_startup::route(
            (
                installed.is_some(),
                signed_v3_was_active,
                pending_profile_is_v3,
                previous_marker.is_some(),
            )
                .into(),
        ) {
            linux_signed_startup::Route::RejectDowngrade => {
                return self.reject_linux_startup_at("route_rejection").await;
            }
            linux_signed_startup::Route::Transition => {
                let Some(installed) = installed.take() else {
                    return self.reject_linux_startup_at("route_rejection").await;
                };
                return match Box::pin(linux_signed_startup::transition_and_install(
                    self, lease, installed,
                ))
                .await
                {
                    Ok(availability) => Ok(availability),
                    Err(_) => self.reject_linux_startup_at("transition_failure").await,
                };
            }
            linux_signed_startup::Route::Baseline | linux_signed_startup::Route::VerifyV3 => {}
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
        #[cfg(target_os = "linux")]
        if let Some(installed) = installed.as_mut()
            && linux_signed_startup::confirm_current_marker(self, installed, previous_marker)
                .await
                .is_err()
        {
            return self.reject_linux_startup_at("verify_v3_failure").await;
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
        drop(installed);
        Ok(RuntimeAvailability::Live)
    }

    async fn reject_current_client(
        &self,
        failure: RuntimeFailureCode,
    ) -> Result<RuntimeAvailability, AppCoreError> {
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
    #[rustfmt::skip]
    async fn reject_linux_startup_at(&self, stage: &'static str) -> Result<RuntimeAvailability, AppCoreError> { linux_signed_startup::diagnostic(stage); self.reject_current_client(RuntimeFailureCode::ProtectedActivationUnavailable).await }
}

#[cfg(target_os = "linux")]
#[path = "connect/linux_signed_startup.rs"]
mod linux_signed_startup;
