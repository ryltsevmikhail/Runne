impl SqliteProviderDispatchStore {
    /// Conservatively recovers an incomplete dispatch from a durable snapshot.
    ///
    /// The compare-and-swap is single-use: it requires the exact durable
    /// fencing token and the exact expected pre-recovery state, and it never
    /// retries blindly after a miss — every failed predicate falls through to
    /// a fresh read and a typed disposition.
    pub fn recover_attempt(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        expected_state: ProviderDispatchState,
    ) -> Result<RecoveryCasOutcome, ProviderStoreError> {
        let expected_state = match expected_state {
            ProviderDispatchState::Dispatching => 1,
            ProviderDispatchState::Streaming => 3,
            ProviderDispatchState::RejectedBeforeEffect
            | ProviderDispatchState::TerminalPendingCommit
            | ProviderDispatchState::Settled
            | ProviderDispatchState::Uncertain => {
                return Err(ProviderStoreError::RecoveryConflict);
            }
        };
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let fencing_token =
            i64::try_from(fencing_token).map_err(|_| ProviderStoreError::StaleFencingToken)?;
        let affected = connection
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = 6
                 WHERE attempt_id = ?1 AND fencing_token = ?2 AND state = ?3",
                params![attempt_id.as_bytes().as_slice(), fencing_token, expected_state],
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        if affected == 1 {
            return Ok(RecoveryCasOutcome::TransitionedToUncertain);
        }
        if affected != 0 {
            return Err(ProviderStoreError::CorruptData);
        }
        let record = load_dispatch_by_attempt(&connection, attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        if fencing_token == 0 || record.fencing_token != fencing_token as u64 {
            return Err(ProviderStoreError::StaleFencingToken);
        }
        match record.state {
            ProviderDispatchState::Settled => Ok(RecoveryCasOutcome::AlreadySettled),
            ProviderDispatchState::Uncertain => Ok(RecoveryCasOutcome::AlreadyUncertain),
            ProviderDispatchState::Dispatching
            | ProviderDispatchState::Streaming
            | ProviderDispatchState::RejectedBeforeEffect
            | ProviderDispatchState::TerminalPendingCommit => {
                Err(ProviderStoreError::RecoveryConflict)
            }
        }
    }
}
