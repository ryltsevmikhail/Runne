impl LocalSessionService {
    /// Builds a service for exactly one daemon launch binding.
    pub fn new(binding: RuntimeSessionBinding, bootstrap_secret: [u8; 32]) -> Self {
        let legacy_identity = *binding.certificate_sha256();
        let legacy_authority = *binding.stable().authority_id();
        Self::with_policy(
            binding,
            legacy_authority,
            legacy_identity,
            bootstrap_secret,
            Arc::new(UnavailableBootstrapReservationStore),
            Arc::new(UnavailableEnrollmentLaunchGenerationStore),
            BootstrapPolicy::ReusableExternal,
            None,
        )
    }

    /// Builds a service with an injected durable bootstrap reservation store.
    pub fn with_reservation_store(
        binding: RuntimeSessionBinding,
        launch_authority_id: [u8; 16],
        executable_sha256: [u8; 32],
        bootstrap_secret: [u8; 32],
        reservation_store: Arc<dyn BootstrapReservationStore>,
    ) -> Self {
        Self::with_policy(
            binding,
            launch_authority_id,
            executable_sha256,
            bootstrap_secret,
            reservation_store,
            Arc::new(UnavailableEnrollmentLaunchGenerationStore),
            BootstrapPolicy::ReusableExternal,
            None,
        )
    }

    /// Builds a service whose bootstrap proof can succeed exactly once before
    /// the supplied monotonic deadline.
    pub fn new_protected(
        binding: RuntimeSessionBinding,
        bootstrap_secret: [u8; 32],
        now: Duration,
        expires_at: Duration,
    ) -> Result<Self, LocalSessionError> {
        if bootstrap_secret == [0; 32]
            || expires_at <= now
            || expires_at.saturating_sub(now) > MAX_PROTECTED_BOOTSTRAP_TTL
        {
            return Err(LocalSessionError::Unauthorized);
        }
        let legacy_identity = *binding.certificate_sha256();
        let legacy_authority = *binding.stable().authority_id();
        Ok(Self::with_policy(
            binding,
            legacy_authority,
            legacy_identity,
            bootstrap_secret,
            Arc::new(UnavailableBootstrapReservationStore),
            Arc::new(UnavailableEnrollmentLaunchGenerationStore),
            BootstrapPolicy::OneTimeProtected,
            Some(expires_at),
        ))
    }

    /// Builds a protected service with an injected durable reservation store.
    pub fn new_protected_with_store(
        binding: RuntimeSessionBinding,
        launch_authority_id: [u8; 16],
        executable_sha256: [u8; 32],
        bootstrap_secret: [u8; 32],
        reservation_store: Arc<dyn BootstrapReservationStore>,
        now: Duration,
        expires_at: Duration,
    ) -> Result<Self, LocalSessionError> {
        Self::new_protected_with_stores(
            binding,
            launch_authority_id,
            executable_sha256,
            bootstrap_secret,
            reservation_store,
            Arc::new(UnavailableEnrollmentLaunchGenerationStore),
            now,
            expires_at,
        )
    }

    /// Builds a protected service with durable bootstrap and generation ports.
    #[allow(clippy::too_many_arguments)]
    pub fn new_protected_with_stores(
        binding: RuntimeSessionBinding,
        launch_authority_id: [u8; 16],
        executable_sha256: [u8; 32],
        bootstrap_secret: [u8; 32],
        reservation_store: Arc<dyn BootstrapReservationStore>,
        enrollment_generation_store: Arc<dyn EnrollmentLaunchGenerationStore>,
        now: Duration,
        expires_at: Duration,
    ) -> Result<Self, LocalSessionError> {
        if launch_authority_id == [0; 16]
            || executable_sha256 == [0; 32]
            || bootstrap_secret == [0; 32]
            || expires_at <= now
            || expires_at.saturating_sub(now) > MAX_PROTECTED_BOOTSTRAP_TTL
        {
            return Err(LocalSessionError::Unauthorized);
        }
        Ok(Self::with_policy(
            binding,
            launch_authority_id,
            executable_sha256,
            bootstrap_secret,
            reservation_store,
            enrollment_generation_store,
            BootstrapPolicy::OneTimeProtected,
            Some(expires_at),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn with_policy(
        binding: RuntimeSessionBinding,
        launch_authority_id: [u8; 16],
        executable_sha256: [u8; 32],
        bootstrap_secret: [u8; 32],
        reservation_store: Arc<dyn BootstrapReservationStore>,
        enrollment_generation_store: Arc<dyn EnrollmentLaunchGenerationStore>,
        bootstrap_policy: BootstrapPolicy,
        bootstrap_expires_at: Option<Duration>,
    ) -> Self {
        Self {
            authorization_epoch: binding.ephemeral().authorization_epoch(),
            sensitivity_ceiling: binding.ephemeral().sensitivity_ceiling(),
            reservation_store,
            enrollment_generation_store,
            pending_enrollment_generation: std::cell::Cell::new(None),
            binding,
            launch_authority_id,
            executable_sha256,
            bootstrap_secret: Some(Zeroizing::new(bootstrap_secret)),
            bootstrap_expires_at,
            bootstrap_policy,
            challenges: HashMap::new(),
            issued: VecDeque::new(),
            sessions: HashMap::new(),
            trusted_clock_origin: std::time::Instant::now(),
        }
    }

    /// Returns the current exact in-memory session binding.
    pub const fn current_binding(&self) -> &RuntimeSessionBinding {
        &self.binding
    }

    /// Exact successor reservation made by this live protected session, if it
    /// is still inside the bounded transition window.
    pub fn pending_protected_enrollment_generation(&self) -> Option<u64> {
        self.pending_protected_enrollment_generation_at(std::time::Instant::now())
    }

    fn pending_protected_enrollment_generation_at(
        &self,
        now: std::time::Instant,
    ) -> Option<u64> {
        self.pending_enrollment_generation
            .get()
            .filter(|(_, deadline)| now < *deadline)
            .map(|(generation, _)| generation)
    }
}
