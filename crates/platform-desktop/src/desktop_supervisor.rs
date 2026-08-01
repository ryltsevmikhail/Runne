/// Host-side supervisor for a single desktop-owned bundled runtime process.
///
/// Authenticated readiness is deliberately reported by the Secure Replay v2
/// profile/session handshake; process stdout cannot mark this supervisor ready.
pub struct BundledRuntimeSupervisor<L, C>
where
    L: BundledRuntimeProcessLauncher,
    C: BundledRuntimeClock,
{
    launcher: L,
    clock: C,
    spec: BundledRuntimeLaunchSpec,
    process: Option<L::Process>,
    profile_binding: Option<BundledRuntimeProfileBinding>,
    backoff: BundledRuntimeBackoff,
    restart_at: Option<Instant>,
    state: BundledRuntimeLifecycleState,
}

impl<L, C> BundledRuntimeSupervisor<L, C>
where
    L: BundledRuntimeProcessLauncher,
    C: BundledRuntimeClock,
{
    #[must_use]
    pub fn new(launcher: L, clock: C, spec: BundledRuntimeLaunchSpec) -> Self {
        Self {
            launcher,
            clock,
            spec,
            process: None,
            profile_binding: None,
            backoff: BundledRuntimeBackoff::new(),
            restart_at: None,
            state: BundledRuntimeLifecycleState::Absent,
        }
    }

    #[must_use]
    pub const fn state(&self) -> BundledRuntimeLifecycleState {
        self.state
    }

    /// Starts the direct bundled executable and waits for an authenticated
    /// Secure Replay v2 readiness callback before becoming ready.
    ///
    /// # Errors
    ///
    /// Returns a typed redacted failure if spawning fails.
    pub fn start(&mut self) -> Result<(), BundledRuntimeSupervisorError> {
        match self.state {
            BundledRuntimeLifecycleState::Absent | BundledRuntimeLifecycleState::FailedStart => {}
            BundledRuntimeLifecycleState::Handshaking | BundledRuntimeLifecycleState::Ready => {
                return Err(BundledRuntimeSupervisorError::AlreadyRunning);
            }
            _ => return Err(BundledRuntimeSupervisorError::InvalidStartState),
        }
        self.spawn_process()
    }

    fn spawn_process(&mut self) -> Result<(), BundledRuntimeSupervisorError> {
        let Some(profile_binding) = self.spec.profile_binding.take() else {
            self.state = BundledRuntimeLifecycleState::FailedStart;
            return Err(BundledRuntimeSupervisorError::ProfileBindingUnavailable);
        };
        self.state = BundledRuntimeLifecycleState::ValidatingBinary;
        self.state = BundledRuntimeLifecycleState::Spawning;
        let Ok(process) = self.launcher.launch(&self.spec) else {
            self.restart_at = None;
            self.state = BundledRuntimeLifecycleState::FailedStart;
            return Err(BundledRuntimeSupervisorError::SpawnFailed);
        };
        self.process = Some(process);
        self.profile_binding = Some(profile_binding);
        self.restart_at = None;
        self.state = BundledRuntimeLifecycleState::Handshaking;
        Ok(())
    }

    /// Accepts readiness only after the authenticated Secure Replay v2
    /// profile/session handshake has completed for this launch.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch when the authenticated session does not prove
    /// the expected current Secure Replay v2 profile binding.
    pub fn record_authenticated_ready(
        &mut self,
        handshake: &BundledRuntimeAuthenticatedHandshake,
    ) -> Result<(), BundledRuntimeSupervisorError> {
        let Some(binding) = self.profile_binding.as_ref() else {
            return Err(BundledRuntimeSupervisorError::HandshakeMismatch);
        };
        if self.process.is_none()
            || self.state != BundledRuntimeLifecycleState::Handshaking
            || !binding.matches(&handshake.identity)
        {
            return Err(BundledRuntimeSupervisorError::HandshakeMismatch);
        }
        self.backoff.record_authenticated_ready(self.clock.now());
        self.state = BundledRuntimeLifecycleState::Ready;
        Ok(())
    }

    /// Fences new supervision work and stops the exact launch proved by the
    /// current Secure Replay v2 session identity.
    ///
    /// A stale handshake cannot stop a replacement launch. If the orderly stop
    /// does not finish within `timeout`, only the process represented by the
    /// existing owned handle is terminated.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when ownership is stale or the owned process
    /// cannot be stopped. It never reports `TaskRun` cancellation success.
    pub fn stop(
        &mut self,
        handshake: &BundledRuntimeAuthenticatedHandshake,
        timeout: Duration,
    ) -> Result<BundledRuntimeStopDisposition, BundledRuntimeSupervisorError> {
        let ownership_matches = self
            .profile_binding
            .as_ref()
            .is_some_and(|binding| binding.matches(&handshake.identity));
        if !matches!(
            self.state,
            BundledRuntimeLifecycleState::Ready | BundledRuntimeLifecycleState::Stopping
        ) || self.process.is_none()
            || !ownership_matches
        {
            return Err(BundledRuntimeSupervisorError::ShutdownOwnershipMismatch);
        }

        let shutdown_was_pending = self.state == BundledRuntimeLifecycleState::Stopping;
        self.state = BundledRuntimeLifecycleState::Stopping;
        self.restart_at = None;
        self.backoff.record_disconnected();
        let stop_status = {
            let Some(process) = self.process.as_mut() else {
                return Err(BundledRuntimeSupervisorError::ShutdownOwnershipMismatch);
            };
            if process.request_graceful_stop().is_err() {
                if !shutdown_was_pending {
                    self.state = BundledRuntimeLifecycleState::Ready;
                }
                return Err(BundledRuntimeSupervisorError::GracefulStopUnavailable);
            }
            process
                .wait_for_exit(timeout)
                .map_err(|_| BundledRuntimeSupervisorError::ProcessStatusUnavailable)?
        };
        if stop_status == BundledRuntimeProcessStatus::Exited {
            self.process = None;
            self.profile_binding = None;
            self.state = BundledRuntimeLifecycleState::Stopped;
            return Ok(BundledRuntimeStopDisposition::Graceful);
        }
        let Some(process) = self.process.as_mut() else {
            return Err(BundledRuntimeSupervisorError::ShutdownOwnershipMismatch);
        };
        process
            .terminate()
            .map_err(|_| BundledRuntimeSupervisorError::ForcedStopUnavailable)?;
        match process.wait_for_exit(timeout) {
            Ok(BundledRuntimeProcessStatus::Exited) => {
                self.process = None;
                self.profile_binding = None;
                self.state = BundledRuntimeLifecycleState::Stopped;
                Ok(BundledRuntimeStopDisposition::Forced)
            }
            Ok(BundledRuntimeProcessStatus::Running) => {
                Err(BundledRuntimeSupervisorError::ForcedStopUnconfirmed)
            }
            Err(_) => Err(BundledRuntimeSupervisorError::ForcedStopUnconfirmed),
        }
    }

    /// Polls the owned child and performs a due bounded restart.
    ///
    /// # Errors
    ///
    /// Returns a typed redacted failure if the process status cannot be read or
    /// a scheduled restart cannot be spawned.
    pub fn monitor(&mut self) -> Result<(), BundledRuntimeSupervisorError> {
        if self.state == BundledRuntimeLifecycleState::Stopped {
            return Ok(());
        }
        if self.state == BundledRuntimeLifecycleState::Stopping {
            let Some(process) = self.process.as_mut() else {
                return Err(BundledRuntimeSupervisorError::ProcessStatusUnavailable);
            };
            if process
                .status()
                .map_err(|_| BundledRuntimeSupervisorError::ProcessStatusUnavailable)?
                == BundledRuntimeProcessStatus::Exited
            {
                self.process = None;
                self.profile_binding = None;
                self.state = BundledRuntimeLifecycleState::Stopped;
            }
            return Ok(());
        }
        let now = self.clock.now();
        if self.state == BundledRuntimeLifecycleState::Ready {
            self.backoff.reset_after_stable_readiness(now);
        }

        if self.state == BundledRuntimeLifecycleState::Backoff
            && self.restart_at.is_some_and(|restart_at| now >= restart_at)
        {
            self.spawn_process()?;
            return Ok(());
        }

        let Some(process) = self.process.as_mut() else {
            return Ok(());
        };
        if process
            .status()
            .map_err(|_| BundledRuntimeSupervisorError::ProcessStatusUnavailable)?
            == BundledRuntimeProcessStatus::Exited
        {
            self.process = None;
            self.profile_binding = None;
            self.state = BundledRuntimeLifecycleState::Crashed;
            match self.backoff.record_unexpected_exit(now) {
                BundledRuntimeRestartDisposition::RestartAfter(delay) => {
                    self.restart_at = Some(now + delay);
                    self.state = BundledRuntimeLifecycleState::Backoff;
                }
                BundledRuntimeRestartDisposition::Exhausted => {
                    self.restart_at = None;
                    self.state = BundledRuntimeLifecycleState::Exhausted;
                }
            }
        }
        Ok(())
    }
}
