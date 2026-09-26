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
        Self::discover_with_provider_activation(
            core,
            desktop_executable,
            runtime_root,
            ProviderActivationBindingV1::openai_responses_text_v1(),
        )
    }

    /// Builds the production supervisor with an explicit native-host provider binding.
    /// # Errors
    /// Returns one closed renderer-safe configuration code. No external
    /// runtime fallback is attempted.
    pub(crate) fn discover_with_provider_activation(
        core: Arc<AppCore>,
        desktop_executable: &std::path::Path,
        runtime_root: &std::path::Path,
        provider_activation: ProviderActivationBindingV1,
    ) -> Result<Arc<Self>, RuntimeFailureCode> {
        let executable =
            discover_bundled_runtime(desktop_executable).map_err(map_protected_failure)?;
        let spec = ProtectedBundledRuntimeLaunchSpec::new(&executable, runtime_root)
            .map_err(map_protected_failure)?
            .with_provider_activation(provider_activation);
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
}
