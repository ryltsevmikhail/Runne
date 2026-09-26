impl LocalSessionService {
    const ENROLLMENT_RESERVATION_TTL: std::time::Duration = std::time::Duration::from_secs(30);

    /// Reserves the exact authoritative successor of the current launch generation.
    ///
    /// Only a `OneTimeProtected` service may reserve, and the authoritative
    /// store must return exactly the current `launch_generation + 1`. The
    /// reservation never mutates the in-memory binding; only
    /// [`LocalSessionService::rotate_protected_enrollment_generation`] consumes
    /// it once through the same authoritative store.
    pub fn reserve_protected_enrollment_generation(&self) -> Result<u64, LocalSessionError> {
        if self.bootstrap_policy != BootstrapPolicy::OneTimeProtected
            || self.pending_protected_enrollment_generation().is_some()
        {
            return Err(LocalSessionError::Unauthorized);
        }
        let Some(expected) = self
            .binding
            .ephemeral()
            .launch_generation()
            .checked_add(1)
        else {
            return Err(LocalSessionError::Unauthorized);
        };
        match self.enrollment_generation_store.reserve_next_enrollment_generation() {
            Ok(reserved) if reserved == expected => {
                let deadline = std::time::Instant::now()
                    .checked_add(Self::ENROLLMENT_RESERVATION_TTL)
                    .ok_or(LocalSessionError::Unavailable)?;
                self.pending_enrollment_generation
                    .set(Some((reserved, deadline)));
                Ok(reserved)
            }
            Ok(_) => Err(LocalSessionError::Unauthorized),
            Err(EnrollmentLaunchGenerationConsumeError::Unavailable) => {
                Err(LocalSessionError::Unavailable)
            }
            Err(EnrollmentLaunchGenerationConsumeError::Rejected) => {
                Err(LocalSessionError::Unauthorized)
            }
        }
    }

    /// Atomically advances one protected enrollment launch to its reserved successor.
    ///
    /// This is intentionally narrower than bootstrap rotation: callers must name the
    /// exact current binding, while the authoritative store consumes `N + 1`.
    pub fn rotate_protected_enrollment_generation(
        &mut self,
        current_binding: &RuntimeSessionBinding,
        next_binding: RuntimeSessionBinding,
        bootstrap_secret: [u8; 32],
        now: Duration,
        expires_at: Duration,
    ) -> Result<(), LocalSessionError> {
        let current_ephemeral = self.binding.ephemeral();
        let next_ephemeral = next_binding.ephemeral();
        let Some(expected_generation) = current_ephemeral.launch_generation().checked_add(1)
        else {
            return Err(LocalSessionError::Unauthorized);
        };
        if self.bootstrap_policy != BootstrapPolicy::OneTimeProtected
            || self.pending_enrollment_generation.get().is_some_and(|(generation, deadline)| {
                generation != expected_generation || std::time::Instant::now() >= deadline
            })
            || current_binding != &self.binding
            || bootstrap_secret == [0; 32]
            || next_ephemeral.launch_generation() != expected_generation
            || self.binding.stable() != next_binding.stable()
            || current_ephemeral.daemon_instance_id() != next_ephemeral.daemon_instance_id()
            || current_ephemeral.session_id() == next_ephemeral.session_id()
            || current_ephemeral.authorization_epoch() != next_ephemeral.authorization_epoch()
            || current_ephemeral.sensitivity_ceiling() != next_ephemeral.sensitivity_ceiling()
            || self.binding.certificate_sha256() != next_binding.certificate_sha256()
            || expires_at <= now
            || expires_at.saturating_sub(now) > MAX_PROTECTED_BOOTSTRAP_TTL
        {
            return Err(LocalSessionError::Unauthorized);
        }
        match self
            .enrollment_generation_store
            .consume_reserved_enrollment_generation(expected_generation)
        {
            Ok(()) => {}
            Err(EnrollmentLaunchGenerationConsumeError::Unavailable) => {
                return Err(LocalSessionError::Unavailable);
            }
            Err(EnrollmentLaunchGenerationConsumeError::Rejected) => {
                return Err(LocalSessionError::Unauthorized);
            }
        }

        self.binding = next_binding;
        self.pending_enrollment_generation.set(None);
        self.bootstrap_secret = Some(Zeroizing::new(bootstrap_secret));
        self.bootstrap_expires_at = Some(expires_at);
        self.challenges.clear();
        for session in self.sessions.values() {
            session.issuer_state.revoked.store(true, Ordering::Release);
        }
        self.sessions.clear();
        Ok(())
    }

    /// Atomically advances one protected enrollment launch to its reserved
    /// successor **and raises the authorization epoch by exactly one**.
    ///
    /// This is the enrollment-transition rotation and the only primitive that
    /// changes the authorization epoch: every authority issued for the prior
    /// epoch is revoked with the rotation, and the service epoch (used by
    /// replay authorization) moves to the same value. The authoritative store
    /// consumes `N + 1` exactly like the generation-only rotation.
    pub fn rotate_protected_enrollment_epoch(
        &mut self,
        current_binding: &RuntimeSessionBinding,
        next_binding: RuntimeSessionBinding,
        bootstrap_secret: [u8; 32],
        now: Duration,
        expires_at: Duration,
    ) -> Result<(), LocalSessionError> {
        let current_ephemeral = self.binding.ephemeral();
        let next_ephemeral = next_binding.ephemeral();
        let Some(expected_generation) = current_ephemeral.launch_generation().checked_add(1)
        else {
            return Err(LocalSessionError::Unauthorized);
        };
        let Some(expected_epoch) = current_ephemeral.authorization_epoch().checked_add(1) else {
            return Err(LocalSessionError::Unauthorized);
        };
        if self.bootstrap_policy != BootstrapPolicy::OneTimeProtected
            || self.pending_enrollment_generation.get().is_some_and(|(generation, deadline)| {
                generation != expected_generation || std::time::Instant::now() >= deadline
            })
            || current_binding != &self.binding
            || bootstrap_secret == [0; 32]
            || next_ephemeral.launch_generation() != expected_generation
            || next_ephemeral.authorization_epoch() != expected_epoch
            || self.binding.stable() != next_binding.stable()
            || current_ephemeral.daemon_instance_id() != next_ephemeral.daemon_instance_id()
            || current_ephemeral.session_id() == next_ephemeral.session_id()
            || current_ephemeral.sensitivity_ceiling() != next_ephemeral.sensitivity_ceiling()
            || self.binding.certificate_sha256() != next_binding.certificate_sha256()
            || expires_at <= now
            || expires_at.saturating_sub(now) > MAX_PROTECTED_BOOTSTRAP_TTL
        {
            return Err(LocalSessionError::Unauthorized);
        }
        match self
            .enrollment_generation_store
            .consume_reserved_enrollment_generation(expected_generation)
        {
            Ok(()) => {}
            Err(EnrollmentLaunchGenerationConsumeError::Unavailable) => {
                return Err(LocalSessionError::Unavailable);
            }
            Err(EnrollmentLaunchGenerationConsumeError::Rejected) => {
                return Err(LocalSessionError::Unauthorized);
            }
        }

        self.binding = next_binding;
        self.pending_enrollment_generation.set(None);
        self.bootstrap_secret = Some(Zeroizing::new(bootstrap_secret));
        self.bootstrap_expires_at = Some(expires_at);
        self.challenges.clear();
        self.set_authorization_epoch(expected_epoch);
        Ok(())
    }
}
