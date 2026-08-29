impl LocalSessionService {
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
        self.bootstrap_secret = Some(Zeroizing::new(bootstrap_secret));
        self.bootstrap_expires_at = Some(expires_at);
        self.challenges.clear();
        for session in self.sessions.values() {
            session.issuer_state.revoked.store(true, Ordering::Release);
        }
        self.sessions.clear();
        Ok(())
    }
}
