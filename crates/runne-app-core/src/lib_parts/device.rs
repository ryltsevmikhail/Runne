impl AppCore {
    /// Returns non-secret metadata for the current desktop runtime session.
    ///
    /// The projection deliberately excludes endpoint, authority, certificate,
    /// session credentials and provider material.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the runtime session cannot be read.
    pub fn runtime_device(&self) -> Result<RuntimeDeviceSnapshot, AppCoreError> {
        let connection = self.effective_runtime_availability()?;
        let client = self.runtime_client()?;
        Ok(RuntimeDeviceSnapshot {
            authenticated: connection == RuntimeAvailability::Live && client.is_some(),
            runtime_version: client
                .as_ref()
                .map(|value| value.session_info().runtime_version.clone()),
            launch_generation: client
                .as_ref()
                .map(|value| value.session_info().launch_generation),
            connection,
        })
    }
}
