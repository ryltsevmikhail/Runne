impl SqliteProviderCredentialLifecycleStore {
    /// Loads the exact active lease after canonical reference validation.
    pub fn active_lease(
        &self,
        provider: &runne_provider::ProviderId,
    ) -> Result<Option<CredentialLease>, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let Some((row, reference)) = load_active_row(&connection, provider)? else {
            return Ok(None);
        };
        validate_row_ref(&row, &reference)?;
        let owner: [u8; 16] = row
            .lease_owner
            .ok_or(CredentialLifecycleError::CorruptState)?
            .try_into()
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
        let expires_at = row
            .lease_expires_at
            .ok_or(CredentialLifecycleError::CorruptState)?;
        let fence = u64::try_from(
            row.lease_fencing_token
                .ok_or(CredentialLifecycleError::CorruptState)?,
        )
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
        CredentialLease::new(reference, owner, expires_at, fence).map(Some)
    }

    /// Allocates the next monotonic provider-local reference without mutation.
    pub fn next_version_ref(
        &self,
        provider: &runne_provider::ProviderId,
    ) -> Result<CredentialVersionRef, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let high_water: i64 = connection
            .query_row(
                "SELECT COALESCE(MAX(credential_version), 0)
                 FROM provider_credential_versions WHERE provider_id=?1",
                [provider.as_str()],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        let next = u64::try_from(high_water)
            .map_err(|_| CredentialLifecycleError::CorruptState)?
            .checked_add(1)
            .ok_or(CredentialLifecycleError::InvalidInput)?;
        CredentialVersionRef::new(provider.clone(), next)
    }

    /// Reads the durable lifecycle state for diagnostics and reconciliation.
    pub fn version_state(
        &self,
        reference: &CredentialVersionRef,
    ) -> Result<CredentialVersionState, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let row = load_row(&connection, reference)?.ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, reference)?;
        Ok(row.state)
    }

    /// Reads a non-secret tombstone digest, if native deletion completed.
    pub fn tombstone_digest(
        &self,
        reference: &CredentialVersionRef,
    ) -> Result<Option<[u8; 32]>, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let row = load_row(&connection, reference)?.ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, reference)?;
        row.tombstone_digest
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| CredentialLifecycleError::CorruptState)
            })
            .transpose()
    }

    /// Reads the current revocation fence without credential material.
    pub fn revocation_fence(
        &self,
        reference: &CredentialVersionRef,
    ) -> Result<u64, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let row = load_row(&connection, reference)?.ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, reference)?;
        u64::try_from(row.revocation_fence).map_err(|_| CredentialLifecycleError::CorruptState)
    }

    /// Counts exact active winners for one provider identity.
    pub fn active_version_count(&self, provider: &str) -> Result<u64, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM provider_credential_versions
                 WHERE provider_id=?1 AND lifecycle_state='ACTIVE'",
                [provider],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        u64::try_from(count).map_err(|_| CredentialLifecycleError::CorruptState)
    }
}
