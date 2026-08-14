impl AppCore {
    /// Opens the application service for one profile database.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the profile cannot be opened or migrated.
    pub fn open(path: &Path) -> Result<Self, AppCoreError> {
        Self::open_internal(path, RuntimeMode::ExternalLocal, None)
    }

    /// Opens the application service with one host-owned runtime profile path.
    ///
    /// The path remains inside the Rust host and is never serialized to the
    /// renderer.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the desktop profile cannot be opened.
    pub fn open_with_runtime_profile(
        path: &Path,
        runtime_profile_path: PathBuf,
    ) -> Result<Self, AppCoreError> {
        Self::open_internal(path, RuntimeMode::ExternalLocal, Some(runtime_profile_path))
    }

    /// Opens the application service with the standard daemon-owned local
    /// runtime profile.
    ///
    /// # Errors
    ///
    /// Returns a storage or platform profile-resolution error.
    pub fn open_with_default_runtime_profile(path: &Path) -> Result<Self, AppCoreError> {
        let profile_path =
            default_local_profile_path().map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Self::open_with_runtime_profile(path, profile_path)
    }

    /// Opens the application service with an explicit host-owned runtime mode.
    ///
    /// Bundled mode remains disconnected until the native supervisor installs
    /// an exact protected client through a one-time activation lease.
    ///
    /// # Errors
    ///
    /// Returns a storage or external-local profile-resolution error.
    pub fn open_with_runtime_mode(
        path: &Path,
        runtime_mode: RuntimeMode,
    ) -> Result<Self, AppCoreError> {
        match runtime_mode {
            RuntimeMode::ExternalLocal => Self::open_with_default_runtime_profile(path),
            RuntimeMode::Bundled => Self::open_internal(path, RuntimeMode::Bundled, None),
        }
    }

    /// Opens the mutation-capable core with an authenticated secure anchor.
    ///
    /// Legacy constructors intentionally remain read-only/offline compatible;
    /// only this explicit construction path admits runtime mutations.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the secure anchor cannot admit the store.
    pub fn open_anchored(
        path: &Path,
        secure: Arc<dyn SecureStore>,
        profile: [u8; 32],
    ) -> Result<Self, AppCoreError> {
        let store = LocalStore::open_anchored(path, secure.as_ref(), profile)
            .map_err(|_| AppCoreError::MutationUnavailable)?;
        Ok(Self::open_store(
            store,
            RuntimeMode::ExternalLocal,
            None,
            Some(MutationSecurityContext { secure }),
        ))
    }

    /// Opens a bundled core whose mutation ledger is secured before the
    /// protected supervisor installs its authenticated client.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the secure anchor cannot admit the store.
    pub fn open_bundled_anchored(
        path: &Path,
        secure: Arc<dyn SecureStore>,
        profile: [u8; 32],
    ) -> Result<Self, AppCoreError> {
        let store = LocalStore::open_anchored(path, secure.as_ref(), profile)
            .map_err(|_| AppCoreError::MutationUnavailable)?;
        Ok(Self::open_store(
            store,
            RuntimeMode::Bundled,
            None,
            Some(MutationSecurityContext { secure }),
        ))
    }

    fn open_internal(
        path: &Path,
        runtime_mode: RuntimeMode,
        runtime_profile_path: Option<PathBuf>,
    ) -> Result<Self, AppCoreError> {
        Ok(Self::open_store(
            LocalStore::open(path)?,
            runtime_mode,
            runtime_profile_path,
            None,
        ))
    }

    fn open_store(
        store: LocalStore,
        runtime_mode: RuntimeMode,
        runtime_profile_path: Option<PathBuf>,
        mutation_security: Option<MutationSecurityContext>,
    ) -> Self {
        let lifecycle = HostLifecycleState::new(runtime_mode);
        let (lifecycle_sender, lifecycle_receiver) =
            tokio::sync::mpsc::channel(HOST_LIFECYCLE_CHANNEL_CAPACITY_V1);
        Self {
            store: Mutex::new(store),
            mutation_security,
            runtime_mode,
            runtime_profile_path,
            runtime_state: RwLock::new(RuntimeAvailability::Unconfigured),
            host_lifecycle: RwLock::new(lifecycle),
            lifecycle_sender,
            lifecycle_event_pipeline: Mutex::new(HostLifecycleEventPipeline::new(lifecycle_receiver)),
            lifecycle_pipeline_closed: AtomicBool::new(false),
            lifecycle_producer_drops: AtomicU64::new(0),
            lifecycle_producer_drop_saturated: AtomicBool::new(false),
            lifecycle_evictions: AtomicU64::new(0),
            lifecycle_eviction_saturated: AtomicBool::new(false),
            bundled_activation_epoch: Mutex::new(0),
            pending_resync_scopes: RwLock::new(HashSet::new()),
            runtime_client: RwLock::new(None),
            runtime_connect: tokio::sync::Mutex::new(()),
            runtime_operation: tokio::sync::Mutex::new(()),
            mutation_gate_epoch: AtomicU64::new(1),
            #[cfg(any(test, feature = "test-support"))]
            mutation_test_hold_before_canonical: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            mutation_test_before_canonical_reached: tokio::sync::Notify::new(),
            #[cfg(any(test, feature = "test-support"))]
            mutation_test_continue_canonical: tokio::sync::Notify::new(),
            #[cfg(any(test, feature = "test-support"))]
            mutation_test_hold_before_dispatch: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            mutation_test_before_dispatch: tokio::sync::Notify::new(),
        }
    }

    /// Opens AppCore with a loopback mock client for transport-bound
    /// integration tests. This hook exists only with explicit test support.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the profile database cannot be opened.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn open_with_mock_runtime(
        path: &Path,
        client: AuthenticatedRuntimeClient,
    ) -> Result<Self, AppCoreError> {
        let profile = [0x41; 32];
        let secure: Arc<dyn SecureStore> = Arc::new(
            gocode_secure_store::test_support::DeterministicSecureStore::new(profile),
        );
        Self::open_with_test_runtime_secure(path, client, secure, profile)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn open_with_test_runtime_secure(
        path: &Path,
        client: AuthenticatedRuntimeClient,
        secure: Arc<dyn SecureStore>,
        profile: [u8; 32],
    ) -> Result<Self, AppCoreError> {
        let core = Self::open_store(
            LocalStore::open_anchored(path, secure.as_ref(), profile)
                .map_err(|_| AppCoreError::MutationUnavailable)?,
            RuntimeMode::ExternalLocal,
            None,
            Some(MutationSecurityContext { secure }),
        );
        *core.runtime_state.write().map_err(|_| AppCoreError::StateUnavailable)? =
            RuntimeAvailability::Live;
        *core.runtime_client.write().map_err(|_| AppCoreError::StateUnavailable)? = Some(client);
        Ok(core)
    }

    /// Returns sanitized renderer bootstrap state.
    ///
    /// # Errors
    ///
    /// Returns an error when state locking, storage or validation fails.
    pub fn bootstrap(&self) -> Result<BootstrapState, AppCoreError> {
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let mut bootstrap = load_bootstrap(&store)?;
        drop(store);
        bootstrap.runtime_mode = self.runtime_mode;
        bootstrap.runtime = self.effective_runtime_availability()?;
        bootstrap.runtime_lifecycle = self.runtime_lifecycle()?;
        bootstrap.runtime_failure = self.runtime_failure()?;
        Ok(bootstrap)
    }

    /// Returns the native host-selected runtime mode.
    #[must_use]
    pub const fn runtime_mode(&self) -> RuntimeMode {
        self.runtime_mode
    }
}
