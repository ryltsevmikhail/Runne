/// Repository-owned SQLite provider dispatch store.
pub struct SqliteProviderDispatchStore {
    connection: Mutex<Connection>,
}

impl SqliteProviderDispatchStore {
    /// Opens the store, applies additive migrations and runs startup gates.
    pub fn open(path: &Path) -> Result<Self, ProviderStoreError> {
        let path = path.to_str().ok_or(ProviderStoreError::Unavailable)?;
        let connection = open_with_pragmas(path).map_err(|_| ProviderStoreError::Unavailable)?;
        apply_migrations(&connection).map_err(|_| ProviderStoreError::Unavailable)?;
        run_startup_gates(&connection, path).map_err(|_| ProviderStoreError::Unavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Persists immutable prepared metadata or returns exact replay.
    pub fn persist_prepared(
        &self,
        record: &PreparedProviderRecord,
    ) -> Result<PersistPreparedOutcome, ProviderStoreError> {
        let record_digest = prepared_record_digest(record);
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        if let Some(stored) = load_prepared(&connection, record.call_id)? {
            return if stored == *record {
                Ok(PersistPreparedOutcome::Replayed)
            } else {
                Err(ProviderStoreError::PreparedConflict)
            };
        }
        connection
            .execute(
                "INSERT INTO provider_prepared_requests
                 (call_id, prepared_digest, render_digest, profile_digest, record_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    record.call_id.as_bytes().as_slice(),
                    record.prepared_digest.as_slice(),
                    record.render_digest.as_slice(),
                    record.profile_digest.as_slice(),
                    record_digest.as_slice(),
                ],
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        Ok(PersistPreparedOutcome::Inserted)
    }

    /// Loads and integrity-checks prepared metadata.
    pub fn get_prepared(
        &self,
        call_id: ProviderCallId,
    ) -> Result<Option<PreparedProviderRecord>, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        load_prepared(&connection, call_id)
    }

    /// Atomically claims one dispatch. Only the insert winner receives permit.
    pub fn claim(
        &self,
        claim: &ProviderDispatchClaim,
    ) -> Result<ProviderClaimOutcome, ProviderStoreError> {
        validate_claim(claim)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let prepared = load_prepared(&transaction, claim.call_id)?
            .ok_or(ProviderStoreError::PreparedMismatch)?;
        if prepared.prepared_digest != claim.prepared_digest
            || prepared.render_digest != claim.render_digest
            || prepared.profile_digest != claim.profile_digest
        {
            return Err(ProviderStoreError::PreparedMismatch);
        }
        if let Some(existing) = load_dispatch_by_attempt(&transaction, claim.attempt_id)? {
            if dispatch_matches_claim(&existing, claim) {
                return Ok(ProviderClaimOutcome::Existing {
                    attempt_id: existing.attempt_id,
                    state: existing.state,
                });
            }
            return Err(ProviderStoreError::ClaimConflict);
        }
        if load_dispatch_by_call(&transaction, claim.call_id)?.is_some() {
            return Err(ProviderStoreError::ClaimConflict);
        }
        insert_dispatch(&transaction, claim)?;
        transaction
            .commit()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        Ok(ProviderClaimOutcome::Winner {
            permit_id: claim.permit_id,
        })
    }

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
            (ProviderDispatchState::Dispatching, None) => {
                connection
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 2, stream_id = ?1 WHERE attempt_id = ?2 AND state = 1",
                        params![
                            request.stream_id.as_bytes().as_slice(),
                            request.attempt_id.as_bytes().as_slice()
                        ],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::Streaming)
            }
            (ProviderDispatchState::Streaming, Some(existing)) if existing == request.stream_id => {
                Ok(ProviderDispatchState::Streaming)
            }
            (ProviderDispatchState::Dispatching, Some(_)) => Err(ProviderStoreError::CorruptData),
            (ProviderDispatchState::Streaming, _) => Err(ProviderStoreError::StreamConflict),
            (ProviderDispatchState::Settled, _) => Err(ProviderStoreError::AlreadyTerminal),
            (ProviderDispatchState::Uncertain, _) => Err(ProviderStoreError::AlreadyTerminal),
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
        connection
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = 3, settlement_digest = ?1 WHERE attempt_id = ?2 AND state IN (1, 2)",
                params![
                    request.settlement_digest.as_slice(),
                    request.attempt_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        Ok(ProviderDispatchState::Settled)
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
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&connection, attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, fencing_token)?;
        match record.state {
            ProviderDispatchState::Settled => Err(ProviderStoreError::AlreadyTerminal),
            ProviderDispatchState::Uncertain => Ok(ProviderDispatchState::Uncertain),
            ProviderDispatchState::Dispatching | ProviderDispatchState::Streaming => {
                connection
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 4 WHERE attempt_id = ?1 AND state IN (1, 2)",
                        [attempt_id.as_bytes().as_slice()],
                    )
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
                "SELECT attempt_id, call_id, permit_id, token_reservation_id,
                        cost_reservation_id, fencing_token, provider_idempotency_key,
                        prepared_digest, render_digest, profile_digest, state,
                        stream_id, settlement_digest
                 FROM provider_dispatch_attempts WHERE state IN (1, 2)
                 ORDER BY attempt_id",
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
