impl SqliteProviderExecutionStore {
    /// Arms one UUIDv7 dispatch ID for the next real admission in test-support builds.
    pub fn arm_next_dispatch_attempt_id_for_test(
        &self,
        dispatch_attempt_id: [u8; 16],
    ) -> Result<(), &'static str> {
        runne_domain::id::validate_uuid_v7_bytes(&dispatch_attempt_id)
            .map_err(|_| "dispatch attempt ID must be UUIDv7")?;
        let mut pending = self
            .next_dispatch_attempt_id_for_test
            .lock()
            .map_err(|_| "dispatch attempt test hook is unavailable")?;
        if pending.is_some() {
            return Err("a dispatch attempt ID is already armed");
        }
        *pending = Some(dispatch_attempt_id);
        Ok(())
    }

    fn take_next_dispatch_attempt_id_for_test(
        &self,
    ) -> Result<Option<[u8; 16]>, ProviderAdmissionError> {
        self.next_dispatch_attempt_id_for_test
            .lock()
            .map(|mut pending| pending.take())
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }
}
