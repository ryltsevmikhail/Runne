
impl SqliteProviderDispatchStore {
    /// Commits or exactly replays terminal evidence pending authoritative completion.
    pub fn mark_terminal_pending(
        &self,
        request: &SettleProviderDispatch,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&transaction, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        match (record.state, record.settlement_digest) {
            (ProviderDispatchState::Streaming, None) => {
                let changed = transaction
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 4, settlement_digest = ?1
                         WHERE attempt_id = ?2 AND state = 3
                           AND settlement_digest IS NULL",
                        params![
                            request.settlement_digest.as_slice(),
                            request.attempt_id.as_bytes().as_slice(),
                        ],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(ProviderStoreError::CorruptData);
                }
                transaction
                    .commit()
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::TerminalPendingCommit)
            }
            (ProviderDispatchState::TerminalPendingCommit, Some(existing))
                if existing == request.settlement_digest =>
            {
                Ok(ProviderDispatchState::TerminalPendingCommit)
            }
            (ProviderDispatchState::Settled, Some(existing))
                if existing == request.settlement_digest =>
            {
                Ok(ProviderDispatchState::Settled)
            }
            (
                ProviderDispatchState::TerminalPendingCommit | ProviderDispatchState::Settled,
                Some(_),
            ) => Err(ProviderStoreError::SettlementConflict),
            (ProviderDispatchState::Dispatching, _) => {
                Err(ProviderStoreError::SettlementBeforeStreaming)
            }
            (ProviderDispatchState::RejectedBeforeEffect | ProviderDispatchState::Uncertain, _) => {
                Err(ProviderStoreError::AlreadyTerminal)
            }
            (ProviderDispatchState::Streaming, Some(_))
            | (ProviderDispatchState::TerminalPendingCommit, None)
            | (ProviderDispatchState::Settled, None) => Err(ProviderStoreError::CorruptData),
        }
    }

    /// Commits terminal settlement or returns exact replay.
    pub fn settle(
        &self,
        request: &SettleProviderDispatch,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&transaction, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        match record.state {
            ProviderDispatchState::Settled => {
                if record.settlement_digest == Some(request.settlement_digest) {
                    Ok(ProviderDispatchState::Settled)
                } else {
                    Err(ProviderStoreError::SettlementConflict)
                }
            }
            ProviderDispatchState::TerminalPendingCommit => {
                if record.settlement_digest != Some(request.settlement_digest) {
                    return Err(ProviderStoreError::SettlementConflict);
                }
                let changed = transaction
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 5 WHERE attempt_id = ?1 AND state = 4",
                        [request.attempt_id.as_bytes().as_slice()],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(ProviderStoreError::CorruptData);
                }
                transaction
                    .commit()
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::Settled)
            }
            ProviderDispatchState::Dispatching => {
                Err(ProviderStoreError::SettlementBeforeStreaming)
            }
            ProviderDispatchState::Streaming => Err(ProviderStoreError::SettlementBeforeTerminal),
            ProviderDispatchState::RejectedBeforeEffect | ProviderDispatchState::Uncertain => {
                Err(ProviderStoreError::AlreadyTerminal)
            }
        }
    }

    /// Loads one durable dispatch record.
    pub fn get_dispatch(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Option<ProviderDispatchRecord>, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        load_dispatch_by_attempt(&connection, attempt_id)
    }

    /// Marks a claimed or streaming dispatch uncertain with expected fencing.
    pub fn mark_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&transaction, attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, fencing_token)?;
        match record.state {
            ProviderDispatchState::RejectedBeforeEffect | ProviderDispatchState::Settled => {
                Err(ProviderStoreError::AlreadyTerminal)
            }
            ProviderDispatchState::Uncertain => Ok(ProviderDispatchState::Uncertain),
            ProviderDispatchState::Dispatching
            | ProviderDispatchState::Streaming
            | ProviderDispatchState::TerminalPendingCommit => {
                let changed = transaction
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 6 WHERE attempt_id = ?1 AND state IN (1, 3, 4)",
                        [attempt_id.as_bytes().as_slice()],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(ProviderStoreError::CorruptData);
                }
                transaction
                    .commit()
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::Uncertain)
            }
        }
    }

    /// Returns incomplete dispatches projected conservatively as uncertain.
    pub fn reopen_incomplete(&self) -> Result<Vec<ProviderDispatchRecord>, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT dispatch.attempt_id, dispatch.call_id, dispatch.permit_id,
                        dispatch.token_reservation_id, dispatch.cost_reservation_id,
                        dispatch.fencing_token, dispatch.provider_idempotency_key,
                        dispatch.prepared_digest, dispatch.render_digest,
                        dispatch.profile_digest, dispatch.state, dispatch.stream_id,
                        dispatch.settlement_digest, dispatch.pre_effect_rejection,
                        prepared.call_digest_version, prepared.record_digest
                 FROM provider_dispatch_attempts AS dispatch
                 JOIN provider_prepared_requests AS prepared
                   ON prepared.call_id = dispatch.call_id
                 WHERE dispatch.state IN (1, 3, 4)
                 ORDER BY dispatch.attempt_id",
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let rows = statement
            .query_map([], decode_dispatch_row)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let mut records = Vec::new();
        for row in rows {
            let mut record = row.map_err(|_| ProviderStoreError::CorruptData)?;
            record.state = ProviderDispatchState::Uncertain;
            records.push(record);
        }
        Ok(records)
    }
}
