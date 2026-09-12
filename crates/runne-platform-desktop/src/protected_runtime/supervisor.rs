
impl DevelopmentBundledRuntimeLauncher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            desktop_host_instance_id: *uuid::Uuid::now_v7().as_bytes(),
        }
    }

    /// Launches one directly measured daemon over an inherited protected
    /// full-duplex channel and waits for exact authenticated readiness.
    ///
    /// # Errors
    ///
    /// Returns a closed failure and reaps the owned child if any admission,
    /// persistence, or readiness check fails.
    pub fn launch(
        &self,
        spec: &ProtectedBundledRuntimeLaunchSpec,
    ) -> Result<ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeError> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = spec;
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(unix)]
        {
            self.launch_unix(spec, &mut LaunchTestControls::production())
        }
        #[cfg(windows)]
        {
            self.launch_windows(spec, &mut LaunchTestControls::production())
        }
    }

    /// Launches with deterministic secret/fault controls for integration tests.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn launch_for_test(
        &self,
        spec: &ProtectedBundledRuntimeLaunchSpec,
        launch_secret: [u8; 32],
        capture_output: bool,
        fail_at: Option<FirstActivationFaultPoint>,
    ) -> Result<ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeError> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (spec, launch_secret, capture_output, fail_at);
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(unix)]
        let mut controls = LaunchTestControls {
            secret_override: Some(Zeroizing::new(launch_secret)),
            capture_output,
            fail_at: fail_at.map(Into::into),
            fault_triggered: false,
        };
        #[cfg(unix)]
        {
            self.launch_unix(spec, &mut controls)
        }
        #[cfg(windows)]
        {
            let mut controls = LaunchTestControls {
                secret_override: Some(Zeroizing::new(launch_secret)),
                capture_output,
                fail_at: fail_at.map(Into::into),
                fault_triggered: false,
            };
            self.launch_windows(spec, &mut controls)
        }
    }

}
