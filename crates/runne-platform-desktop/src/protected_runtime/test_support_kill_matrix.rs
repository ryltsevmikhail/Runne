// Test-support accessors added for the D1.6 kill matrix: exact owned child
// identity, bounded exit reaping and captured output diagnosis on the
// supervisor, mirroring the process-level helpers in tests.rs.

impl ProtectedBundledRuntimeSupervisor {
    /// Returns the OS process ID of the supervisor's running child,
    /// test-support only: the D1.6 kill matrix SIGKILLs the exact owned
    /// daemon at an armed pipeline boundary (see `test_owned_child_id`).
    #[cfg(all(feature = "test-support", unix))]
    #[doc(hidden)]
    #[must_use]
    pub fn test_owned_child_id(&self) -> u32 {
        self.process
            .as_ref()
            .expect("supervised process is running")
            .test_owned_child_id()
    }

    /// Waits until the supervised child exits, test-support only: the kill
    /// matrix must reap the SIGKILLed daemon before relaunching on the same
    /// durable root (same contract as `ProtectedBundledRuntimeProcess`).
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_wait_for_exit(
        &mut self,
        timeout: Duration,
    ) -> Result<BundledRuntimeProcessStatus, ProtectedBundledRuntimeError> {
        self.process
            .as_mut()
            .map_or(Ok(BundledRuntimeProcessStatus::Exited), |process| {
                process.wait_for_exit(timeout)
            })
    }

    /// Takes the captured daemon output for diagnosis, test-support only.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_take_captured_output(&mut self) -> Option<String> {
        let (stdout, stderr) = self
            .process
            .as_mut()
            .expect("supervised process is running")
            .take_captured_output_for_test()
            .ok()?;
        Some(format!(
            "--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        ))
    }
}
