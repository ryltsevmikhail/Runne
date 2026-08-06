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

    fn open_internal(
        path: &Path,
        runtime_mode: RuntimeMode,
        runtime_profile_path: Option<PathBuf>,
    ) -> Result<Self, AppCoreError> {
        let lifecycle = HostLifecycleState::new(runtime_mode);
        let (lifecycle_sender, lifecycle_receiver) =
            tokio::sync::mpsc::channel(HOST_LIFECYCLE_CHANNEL_CAPACITY_V1);
        Ok(Self {
            store: Mutex::new(LocalStore::open(path)?),
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
        })
    }

    /// Opens AppCore with a loopback mock client for transport-bound
    /// integration tests. This hook is unavailable in release builds.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the profile database cannot be opened.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn open_with_mock_runtime(
        path: &Path,
        client: AuthenticatedRuntimeClient,
    ) -> Result<Self, AppCoreError> {
        let lifecycle = HostLifecycleState::new(RuntimeMode::ExternalLocal);
        let (lifecycle_sender, lifecycle_receiver) =
            tokio::sync::mpsc::channel(HOST_LIFECYCLE_CHANNEL_CAPACITY_V1);
        Ok(Self {
            store: Mutex::new(LocalStore::open(path)?),
            runtime_mode: RuntimeMode::ExternalLocal,
            runtime_profile_path: None,
            runtime_state: RwLock::new(RuntimeAvailability::Live),
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
            runtime_client: RwLock::new(Some(client)),
            runtime_connect: tokio::sync::Mutex::new(()),
            runtime_operation: tokio::sync::Mutex::new(()),
        })
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn force_runtime_reconnecting_for_test(&self) -> Result<(), AppCoreError> {
        self.set_runtime_failure(RuntimeAvailability::Reconnecting)
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn force_pending_resync_for_test(&self) -> Result<(), AppCoreError> {
        self.set_resync_required_for_scope(ReplayScopeKey {
            runtime_authority: "test-authority".to_owned(),
            principal: "test-principal".to_owned(),
            lineage: "test-lineage".to_owned(),
            scope: "test-scope".to_owned(),
            binding_digest: "11".repeat(32),
        })
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
