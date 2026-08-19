struct SqliteNativeCreateValidator {
    connection: Arc<Mutex<ManagedConnection>>,
    operation_id: [u8; 16],
    source_revision_id: [u8; 16],
    reference: CredentialVersionRef,
}

impl CredentialNativeCreateValidator for SqliteNativeCreateValidator {
    fn validate(&self) -> Result<(), CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        let provision = load_provision_by_operation(&connection, self.operation_id)?
            .ok_or(CredentialLifecycleError::NotFound)?;
        if provision.source_revision_id != self.source_revision_id
            || provision.reference != self.reference
            || provision.stage != ProvisionStage::Prepared
        {
            return Err(CredentialLifecycleError::StaleLease);
        }
        let row = load_row(&connection, &self.reference)?
            .ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, &self.reference)?;
        if row.state != CredentialVersionState::Prepared || row.tombstone_digest.is_some() {
            return Err(CredentialLifecycleError::StaleLease);
        }
        Ok(())
    }
}
