impl SqliteProviderExecutionStore {
    fn revalidate_provider_poll_impl(&self, request: &ProviderPollRequest) -> Result<(), ProviderExecutionError> {
        validate_poll_request(request)?;
        let mut connection = self.connection.lock().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection.transaction().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&transaction, request.attempt_id)?;
        verify_attempt_for_progress(&attempt, request.fencing_token, request.runtime_generation, request.profile_digest)?;
        verify_current_runtime_lease(&transaction, &attempt)?;
        super::dispatch_store::verify_online_publication(&transaction, request.attempt_id, Some(self.now()))
            .map_err(|error| match error {
                super::dispatch_store::ProviderStoreError::Unavailable => ProviderExecutionError::StoreUnavailable,
                _ => ProviderExecutionError::StaleGeneration,
            })?;
        if attempt.state == 6 { return Err(ProviderExecutionError::AttemptUncertain); }
        if attempt.state != 3 { return Err(ProviderExecutionError::TerminalConflict); }
        if next_journal_sequence(&transaction, request.attempt_id)? != request.cursor {
            return Err(ProviderExecutionError::SequenceMismatch);
        }
        let exact: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_poll_flights WHERE dispatch_attempt_id=?1
             AND cursor=?2 AND runtime_generation=?3 AND fencing_token=?4)",
            params![request.attempt_id.as_bytes().as_slice(), execution_i64(request.cursor)?,
                execution_i64(request.runtime_generation)?, execution_i64(request.fencing_token)?],
            |row| row.get(0),
        ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if !exact { return Err(ProviderExecutionError::PollNotArmed); }
        transaction.commit().map_err(|_| ProviderExecutionError::StoreUnavailable)
    }
}
