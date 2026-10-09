type CapturedRuntimeOutputForTest = (BundledRuntimeStopDisposition, (Vec<u8>, Vec<u8>));

impl ProtectedBundledRuntimeSupervisor {
    /// Starts one owned test daemon with actual stdout/stderr capture.
    #[doc(hidden)]
    pub fn start_capturing_for_test(
        &mut self,
        launch_secret: [u8; 32],
    ) -> Result<(), ProtectedBundledRuntimeError> {
        start_protected_runtime_with(self, |launcher, spec| {
            launcher.launch_for_test(spec, launch_secret, true, None)
        })
    }

    /// Stops the owned test daemon and returns its captured stdout and stderr.
    #[doc(hidden)]
    pub fn stop_capturing_for_test(
        &mut self,
    ) -> Result<CapturedRuntimeOutputForTest, ProtectedBundledRuntimeError> {
        let (disposition, process) = self.stop_with()?;
        let mut process = process.ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let output = process.take_captured_output_for_test()?;
        Ok((disposition, output))
    }
}
