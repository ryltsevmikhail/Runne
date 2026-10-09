impl ProtectedBundledRuntimeSupervisor {
    #[must_use]
    pub fn new(
        launcher: DevelopmentBundledRuntimeLauncher,
        spec: ProtectedBundledRuntimeLaunchSpec,
    ) -> Self {
        Self {
            launcher,
            spec,
            process: None,
            pending_profile: None,
            backoff: BundledRuntimeBackoff::new(),
            restart_at: None,
            state: BundledRuntimeLifecycleState::Absent,
            #[cfg(all(target_os = "linux", feature = "protected-channel-integration"))]
            permission_control_sequence: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            credential_service_rejoin: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> BundledRuntimeLifecycleState {
        self.state
    }

    #[must_use]
    pub const fn owns_runtime(&self) -> bool {
        self.process.is_some()
    }

    /// Starts one fresh protected activation. No external fallback exists.
    ///
    /// # Errors
    ///
    /// Returns a closed launch or lifecycle failure.
    pub fn start(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        start_protected_runtime_with(self, DevelopmentBundledRuntimeLauncher::launch)
    }

    fn spawn_fresh(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        self.spawn_fresh_with(DevelopmentBundledRuntimeLauncher::launch)
    }

    fn spawn_fresh_with(
        &mut self,
        launch: impl FnOnce(
            &DevelopmentBundledRuntimeLauncher,
            &ProtectedBundledRuntimeLaunchSpec,
        )
            -> Result<ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeError>,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        #[cfg(all(target_os = "linux", feature = "protected-channel-integration"))]
        {
            self.permission_control_sequence = None;
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            self.credential_service_rejoin = None;
        }
        self.pending_profile = None;
        self.restart_at = None;
        self.state = BundledRuntimeLifecycleState::ValidatingBinary;
        self.state = BundledRuntimeLifecycleState::Spawning;
        let mut process = launch(&self.launcher, &self.spec)?;
        let profile = process
            .take_runtime_profile()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        self.pending_profile = Some(profile);
        self.process = Some(process);
        self.state = BundledRuntimeLifecycleState::Handshaking;
        Ok(())
    }

    /// Moves the current one-time profile to the native `AppCore` integration.
    pub const fn take_runtime_profile(&mut self) -> Option<ProtectedBundledRuntimeProfile> {
        self.pending_profile.take()
    }

    /// Accepts ready only after the protected runne-runtime-client handshake matches
    /// the current exact ownership tuple.
    ///
    /// # Errors
    ///
    /// Returns a closed ownership mismatch for stale or downgraded clients.
    pub fn record_client_ready(
        &mut self,
        client: &AuthenticatedRuntimeClient,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Handshaking
            || self.pending_profile.is_some()
            || !self
                .process
                .as_ref()
                .is_some_and(|process| process.matches_client(client))
        {
            self.state = BundledRuntimeLifecycleState::IdentityMismatch;
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        self.backoff.record_authenticated_ready(Instant::now());
        self.state = BundledRuntimeLifecycleState::Ready;
        Ok(())
    }

    /// Rotates the one-time HTTP session for the currently owned runtime.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, renewal, proof, or channel failure.
    pub fn renew_profile(
        &mut self,
    ) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let profile = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .renew_profile()?;
        self.backoff.record_disconnected();
        self.state = BundledRuntimeLifecycleState::Handshaking;
        Ok(profile)
    }

    /// Queues a freshly rotated one-time profile for the native `AppCore`
    /// integration. The previous daemon HTTP session is invalidated before
    /// this method returns.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, renewal, proof, or channel failure.
    pub fn queue_renewal_profile(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        let profile = self.renew_profile()?;
        self.pending_profile = Some(profile);
        Ok(())
    }

    /// Handles a failed HTTP bootstrap without admitting a downgraded mode.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, shutdown, or restart-budget failure.
    pub fn record_client_failure(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        if !matches!(
            self.state,
            BundledRuntimeLifecycleState::Handshaking
                | BundledRuntimeLifecycleState::Ready
                | BundledRuntimeLifecycleState::IdentityMismatch
        ) {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.pending_profile = None;
        if let Some(process) = self.process.as_mut() {
            let _ = process.request_graceful_stop();
            if process.wait_for_exit(Duration::from_secs(1))?
                == BundledRuntimeProcessStatus::Running
            {
                process.terminate()?;
                if process.wait_for_exit(Duration::from_secs(1))?
                    != BundledRuntimeProcessStatus::Exited
                {
                    return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
                }
            }
        }
        self.process = None;
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            self.credential_service_rejoin = None;
        }
        self.schedule_restart(Instant::now())
    }

    /// Polls the owned child and performs only due bounded fresh activations.
    ///
    /// # Errors
    ///
    /// Returns a closed process, relaunch, or restart-budget failure.
    pub fn monitor(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        if matches!(
            self.state,
            BundledRuntimeLifecycleState::Stopped
                | BundledRuntimeLifecycleState::Absent
                | BundledRuntimeLifecycleState::FailedStart
                | BundledRuntimeLifecycleState::Exhausted
        ) {
            return Ok(());
        }
        let now = Instant::now();
        if self.state == BundledRuntimeLifecycleState::Ready {
            self.backoff.reset_after_stable_readiness(now);
        }
        if self.state == BundledRuntimeLifecycleState::Backoff {
            if self.restart_at.is_some_and(|restart_at| now >= restart_at)
                && let Err(error) = self.spawn_fresh()
            {
                self.process = None;
                self.pending_profile = None;
                self.schedule_restart(now)?;
                return Err(error);
            }
            return Ok(());
        }
        let exited = self
            .process
            .as_mut()
            .map(ProtectedBundledRuntimeProcess::status)
            .transpose()?
            .is_some_and(|status| status == BundledRuntimeProcessStatus::Exited);
        if exited {
            self.process = None;
            self.pending_profile = None;
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            {
                self.credential_service_rejoin = None;
            }
            self.state = BundledRuntimeLifecycleState::Crashed;
            self.schedule_restart(now)?;
        }
        Ok(())
    }

    fn schedule_restart(&mut self, now: Instant) -> Result<(), ProtectedBundledRuntimeError> {
        self.backoff.record_disconnected();
        match self.backoff.record_unexpected_exit(now) {
            BundledRuntimeRestartDisposition::RestartAfter(delay) => {
                self.restart_at = Some(now + delay);
                self.state = BundledRuntimeLifecycleState::Backoff;
                Ok(())
            }
            BundledRuntimeRestartDisposition::Exhausted => {
                self.restart_at = None;
                self.state = BundledRuntimeLifecycleState::Exhausted;
                Err(ProtectedBundledRuntimeError::RestartExhausted)
            }
        }
    }

    /// Stops only the exact currently owned child. External runtimes are never
    /// represented by this supervisor and therefore cannot be terminated here.
    ///
    /// # Errors
    ///
    /// Returns a closed ownership or incomplete-shutdown failure.
    pub fn stop(&mut self) -> Result<BundledRuntimeStopDisposition, ProtectedBundledRuntimeError> {
        self.stop_with().map(|(disposition, _process)| disposition)
    }

    fn stop_with(
        &mut self,
    ) -> Result<
        (
            BundledRuntimeStopDisposition,
            Option<ProtectedBundledRuntimeProcess>,
        ),
        ProtectedBundledRuntimeError,
    > {
        self.restart_at = None;
        self.pending_profile = None;
        self.backoff.record_disconnected();
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            self.credential_service_rejoin = None;
        }
        let Some(mut process) = self.process.take() else {
            self.state = BundledRuntimeLifecycleState::Stopped;
            return Ok((BundledRuntimeStopDisposition::Graceful, None));
        };
        self.state = BundledRuntimeLifecycleState::Stopping;
        let graceful_requested = process.request_graceful_stop().is_ok();
        if graceful_requested
            && process.wait_for_exit(BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT)?
                == BundledRuntimeProcessStatus::Exited
        {
            self.state = BundledRuntimeLifecycleState::Stopped;
            return Ok((BundledRuntimeStopDisposition::Graceful, Some(process)));
        }
        process.terminate()?;
        if process.wait_for_exit(BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT)?
            != BundledRuntimeProcessStatus::Exited
        {
            self.process = Some(process);
            return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
        }
        self.state = BundledRuntimeLifecycleState::Stopped;
        Ok((BundledRuntimeStopDisposition::Forced, Some(process)))
    }
}
