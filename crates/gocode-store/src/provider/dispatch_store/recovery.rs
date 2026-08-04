impl SqliteProviderDispatchStore {
    /// Binds a normalized stream with expected-fence idempotency.
    pub fn mark_streaming(
        &self,
        request: &MarkProviderStreaming,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&connection, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        match (record.state, record.stream_id) {
            (ProviderDispatchState::Dispatching, None) => {}
            (ProviderDispatchState::Streaming, Some(existing)) if existing == request.stream_id => {
                return Ok(ProviderDispatchState::Streaming);
            }
            (ProviderDispatchState::Dispatching, Some(_)) => {
                return Err(ProviderStoreError::CorruptData);
            }
            (ProviderDispatchState::Streaming, _) => return Err(ProviderStoreError::StreamConflict),
            (ProviderDispatchState::Settled | ProviderDispatchState::Uncertain, _) => {
                return Err(ProviderStoreError::AlreadyTerminal);
            }
        }
        let affected = connection
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = 2, stream_id = ?1 WHERE attempt_id = ?2 AND state = 1",
                params![
                    request.stream_id.as_bytes().as_slice(),
                    request.attempt_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        if affected == 1 {
            return Ok(ProviderDispatchState::Streaming);
        }
        if affected != 0 {
            return Err(ProviderStoreError::CorruptData);
        }
        let record = load_dispatch_by_attempt(&connection, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        match (record.state, record.stream_id) {
            (ProviderDispatchState::Streaming, Some(existing)) if existing == request.stream_id => {
                Ok(ProviderDispatchState::Streaming)
            }
            (ProviderDispatchState::Streaming, _) => Err(ProviderStoreError::StreamConflict),
            (ProviderDispatchState::Settled | ProviderDispatchState::Uncertain, _) => {
                Err(ProviderStoreError::AlreadyTerminal)
            }
            (ProviderDispatchState::Dispatching, _) => Err(ProviderStoreError::RecoveryConflict),
        }
    }

    /// Commits terminal settlement or returns exact replay.
    pub fn settle(
        &self,
        request: &SettleProviderDispatch,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&connection, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        if record.state == ProviderDispatchState::Settled {
            return if record.settlement_digest == Some(request.settlement_digest) {
                Ok(ProviderDispatchState::Settled)
            } else {
                Err(ProviderStoreError::SettlementConflict)
            };
        }
        if record.state == ProviderDispatchState::Uncertain {
            return Err(ProviderStoreError::AlreadyTerminal);
        }
        let affected = connection
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = 3, settlement_digest = ?1 WHERE attempt_id = ?2 AND state IN (1, 2)",
                params![
                    request.settlement_digest.as_slice(),
                    request.attempt_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        if affected == 1 {
            return Ok(ProviderDispatchState::Settled);
        }
        if affected != 0 {
            return Err(ProviderStoreError::CorruptData);
        }
        let record = load_dispatch_by_attempt(&connection, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        match record.state {
            ProviderDispatchState::Settled if record.settlement_digest == Some(request.settlement_digest) => {
                Ok(ProviderDispatchState::Settled)
            }
            ProviderDispatchState::Settled => Err(ProviderStoreError::SettlementConflict),
            ProviderDispatchState::Uncertain => Err(ProviderStoreError::AlreadyTerminal),
            ProviderDispatchState::Dispatching | ProviderDispatchState::Streaming => {
                Err(ProviderStoreError::RecoveryConflict)
            }
        }
    }

    /// Conservatively recovers an incomplete dispatch from a durable snapshot.
    pub fn recover_attempt(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        expected_state: ProviderDispatchState,
    ) -> Result<RecoveryCasOutcome, ProviderStoreError> {
        let expected_state = match expected_state {
            ProviderDispatchState::Dispatching => 1,
            ProviderDispatchState::Streaming => 2,
            ProviderDispatchState::Settled | ProviderDispatchState::Uncertain => {
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
                 SET state = 4
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
            ProviderDispatchState::Dispatching | ProviderDispatchState::Streaming => {
                Err(ProviderStoreError::RecoveryConflict)
            }
        }
    }
}
