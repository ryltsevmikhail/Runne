impl AppCore {
    /// Returns the authenticated runtime's metadata-only provider projection.
    ///
    /// Provider credentials, secure-store errors, endpoint material and paths
    /// never cross this application boundary.
    ///
    /// # Errors
    ///
    /// Returns a closed error when no authenticated runtime projection exists.
    pub fn provider_statuses(&self) -> Result<Vec<ProviderStatusSnapshotV1>, AppCoreError> {
        let client = self
            .runtime_client()?
            .ok_or(AppCoreError::RuntimeUnavailable)?;
        let statuses = client.provider_statuses();
        if statuses.is_empty() {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        Ok(statuses.to_vec())
    }
}
