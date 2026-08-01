impl BundledRuntimeController {
    /// Discovers and pins the colocated daemon before creating its supervisor.
    ///
    /// # Errors
    ///
    /// Returns one closed renderer-safe code. No external runtime fallback is
    /// attempted.
    pub fn discover(
        core: Arc<AppCore>,
        desktop_executable: &std::path::Path,
        runtime_root: &std::path::Path,
    ) -> Result<Arc<Self>, RuntimeFailureCode> {
        let executable =
            discover_bundled_runtime(desktop_executable).map_err(map_protected_failure)?;
        let spec = ProtectedBundledRuntimeLaunchSpec::new(&executable, runtime_root)
            .map_err(map_protected_failure)?;
        let supervisor =
            ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
        Ok(Arc::new(Self {
            core,
            supervisor: Arc::new(Mutex::new(supervisor)),
            operation_fence: RuntimeOperationFence::new(),
            renewal_schedule: Mutex::new(ProtectedSessionRenewalSchedule::new(
                PROTECTED_BUNDLED_SESSION_RENEW_AFTER,
            )),
            shutdown_outcome: Mutex::new(None),
        }))
    }

    /// Starts the bounded monitor on the native async runtime.
    pub fn spawn_monitor(self: &Arc<Self>) {
        let controller = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            controller.monitor_loop().await;
        });
    }

    #[must_use]
    pub fn shutdown_outcome(&self) -> Option<BundledShutdownOutcome> {
        self.shutdown_outcome
            .lock()
            .map_or(Some(BundledShutdownOutcome::Incomplete), |outcome| *outcome)
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
        self.connect_pending_profile(lease).await
    }

    async fn connect_pending_profile(
        &self,
        lease: BundledRuntimeActivationLease,
    ) -> Result<RuntimeAvailability, AppCoreError> {
        let profile = self
            .supervisor
            .lock()
            .map(|mut supervisor| supervisor.take_runtime_profile())
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
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

}
