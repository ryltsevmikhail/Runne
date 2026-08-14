impl SqliteProviderDispatchStore {
    /// Opens the store, applies additive migrations and runs startup gates.
    pub fn open(path: &Path) -> Result<Self, ProviderStoreError> {
        let path = path.to_str().ok_or(ProviderStoreError::Unavailable)?;
        let connection = open_managed_connection(Path::new(path), ConnectionMode::Writer)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        Self::open_with_connection(path, connection)
    }

    /// Adopts a validated writable connection without reopening its path.
    pub fn open_with_connection(
        _path: &str,
        connection: ManagedConnection,
    ) -> Result<Self, ProviderStoreError> {
        apply_migrations(&connection).map_err(|_| ProviderStoreError::Unavailable)?;
        readiness_from_managed(&connection).map_err(|_| ProviderStoreError::Unavailable)?;
        publication_from_managed(&connection).map_err(|_| ProviderStoreError::Unavailable)?;
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
                 (call_id, prepared_digest, render_digest, profile_digest, record_digest,
                  call_digest_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    record.call_id.as_bytes().as_slice(),
                    record.prepared_digest.as_slice(),
                    record.render_digest.as_slice(),
                    record.profile_digest.as_slice(),
                    record_digest.as_slice(),
                    encode_digest_version(record.call_digest_version),
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

    /// Rejects the retired caller-selected V12 claim path.
    ///
    /// V13 inserts a claim only through the runtime authority issuer, in the
    /// same transaction as semantic admission and both budget reservations.
    pub fn claim(
        &self,
        _claim: &ProviderDispatchClaim,
    ) -> Result<ProviderClaimOutcome, ProviderStoreError> {
        Err(ProviderStoreError::LegacyClaimDisabled)
    }

    /// Binds a normalized stream with expected-fence idempotency.
    pub fn mark_streaming(
        &self,
        request: &MarkProviderStreaming,
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
        match (record.state, record.stream_id) {
            (ProviderDispatchState::Dispatching, None) => {
                let changed = transaction
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 3, stream_id = ?1 WHERE attempt_id = ?2 AND state = 1",
                        params![
                            request.stream_id.as_bytes().as_slice(),
                            request.attempt_id.as_bytes().as_slice()
                        ],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(ProviderStoreError::CorruptData);
                }
                transaction
                    .commit()
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::Streaming)
            }
            (ProviderDispatchState::Streaming, Some(existing)) if existing == request.stream_id => {
                Ok(ProviderDispatchState::Streaming)
            }
            (ProviderDispatchState::Dispatching, Some(_)) => Err(ProviderStoreError::CorruptData),
            (ProviderDispatchState::Streaming, _) => Err(ProviderStoreError::StreamConflict),
            (
                ProviderDispatchState::RejectedBeforeEffect
                | ProviderDispatchState::TerminalPendingCommit
                | ProviderDispatchState::Settled
                | ProviderDispatchState::Uncertain,
                _,
            ) => Err(ProviderStoreError::AlreadyTerminal),
        }
    }

    /// Commits or exactly replays a typed rejection proved to precede dispatch.
    pub fn mark_rejected_before_effect(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        rejection: ProviderPreEffectRejection,
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
        match (record.state, record.pre_effect_rejection) {
            (ProviderDispatchState::Dispatching, None) => {
                let changed = transaction
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 2, pre_effect_rejection = ?1
                         WHERE attempt_id = ?2 AND state = 1
                           AND pre_effect_rejection IS NULL",
                        params![
                            encode_pre_effect_rejection(rejection),
                            attempt_id.as_bytes().as_slice(),
                        ],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(ProviderStoreError::CorruptData);
                }
                transaction
                    .commit()
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::RejectedBeforeEffect)
            }
            (ProviderDispatchState::RejectedBeforeEffect, Some(existing))
                if existing == rejection =>
            {
                Ok(ProviderDispatchState::RejectedBeforeEffect)
            }
            (ProviderDispatchState::RejectedBeforeEffect, Some(_)) => {
                Err(ProviderStoreError::RejectionConflict)
            }
            (ProviderDispatchState::Dispatching, Some(_))
            | (ProviderDispatchState::RejectedBeforeEffect, None) => {
                Err(ProviderStoreError::CorruptData)
            }
            (
                ProviderDispatchState::Streaming
                | ProviderDispatchState::TerminalPendingCommit
                | ProviderDispatchState::Settled
                | ProviderDispatchState::Uncertain,
                _,
            ) => Err(ProviderStoreError::AlreadyTerminal),
        }
    }
}
