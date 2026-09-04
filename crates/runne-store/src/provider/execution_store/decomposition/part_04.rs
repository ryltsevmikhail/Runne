impl SqliteProviderExecutionStore {
    fn append_encrypted_event_impl(
        &self,
        request: &ProviderJournalAppendRequest,
    ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> {
        validate_journal_append(request)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&transaction, request.attempt_id)?;
        verify_attempt_for_progress(
            &attempt,
            request.fencing_token,
            request.runtime_generation,
            request.profile_digest,
        )?;
        verify_current_runtime_lease(&transaction, &attempt)?;
        super::dispatch_store::verify_online_publication(
            &transaction,
            request.attempt_id,
            Some(self.now()),
        )
        .map_err(|error| match error {
            super::dispatch_store::ProviderStoreError::Unavailable => {
                ProviderExecutionError::StoreUnavailable
            }
            _ => ProviderExecutionError::StaleGeneration,
        })?;
        if attempt.state == 6 {
            return Err(ProviderExecutionError::AttemptUncertain);
        }
        if attempt.state != 3 {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        if attempt.call_digest_version != request.call_digest_version {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        ensure_active_journal_key(&transaction, request.key, &attempt)?;

        if let Some(existing) =
            load_encrypted_event(&transaction, request.attempt_id, request.sequence)?
        {
            return if existing == *request {
                Ok(ProviderJournalAppendOutcome::Replayed)
            } else {
                Err(ProviderExecutionError::JournalCorrupt)
            };
        }
        let armed: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM provider_poll_flights
                    WHERE dispatch_attempt_id = ?1 AND cursor = ?2
                      AND runtime_generation = ?3 AND fencing_token = ?4
                 )",
                params![
                    request.attempt_id.as_bytes().as_slice(),
                    execution_i64(request.sequence)?,
                    execution_i64(request.runtime_generation)?,
                    execution_i64(request.fencing_token)?,
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if !armed {
            return Err(ProviderExecutionError::PollNotArmed);
        }
        let next_sequence = next_journal_sequence(&transaction, request.attempt_id)?;
        if request.sequence != next_sequence {
            return Err(ProviderExecutionError::SequenceMismatch);
        }
        let terminal_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM provider_stream_journal
                    WHERE dispatch_attempt_id = ?1 AND terminal = 1
                 )",
                [request.attempt_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if terminal_exists {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        insert_nonce(
            &transaction,
            request.key,
            request.encrypted.nonce(),
            1,
            request.attempt_id,
            Some(request.sequence),
        )?;
        transaction
            .execute(
                "INSERT INTO provider_stream_journal (
                    dispatch_attempt_id, sequence, key_id, key_version, nonce,
                    call_digest_version, profile_digest, runtime_generation,
                    event_kind, terminal, ciphertext, plaintext_len, plaintext_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    request.attempt_id.as_bytes().as_slice(),
                    execution_i64(request.sequence)?,
                    request.key.key_id().as_slice(),
                    execution_i64(request.key.key_version())?,
                    request.encrypted.nonce().as_slice(),
                    encode_call_digest_version(request.call_digest_version),
                    request.profile_digest.as_slice(),
                    execution_i64(request.runtime_generation)?,
                    i64::from(request.event_kind),
                    i64::from(request.terminal),
                    request.encrypted.ciphertext(),
                    execution_i64(request.encrypted.plaintext_len())?,
                    request.encrypted.plaintext_digest().as_slice(),
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let closed = transaction
            .execute(
                "DELETE FROM provider_poll_flights
                 WHERE dispatch_attempt_id = ?1 AND cursor = ?2
                   AND runtime_generation = ?3 AND fencing_token = ?4",
                params![
                    request.attempt_id.as_bytes().as_slice(),
                    execution_i64(request.sequence)?,
                    execution_i64(request.runtime_generation)?,
                    execution_i64(request.fencing_token)?,
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if closed != 1 {
            return Err(ProviderExecutionError::PollNotArmed);
        }
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        Ok(ProviderJournalAppendOutcome::Inserted)
    }

}
impl SqliteProviderExecutionStore {
    fn load_encrypted_events_impl(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&connection, attempt_id)?;
        let mut statement = connection
            .prepare(
                "SELECT journal.sequence, journal.key_id, journal.key_version,
                        keys.runtime_authority_id, keys.database_generation,
                        journal.nonce, journal.call_digest_version, journal.profile_digest,
                        journal.runtime_generation, journal.event_kind, journal.terminal,
                        journal.ciphertext, journal.plaintext_len, journal.plaintext_digest
                 FROM provider_stream_journal journal
                 JOIN provider_journal_key_refs keys
                   ON keys.key_id = journal.key_id AND keys.key_version = journal.key_version
                 WHERE journal.dispatch_attempt_id = ?1
                 ORDER BY journal.sequence",
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let rows = statement
            .query_map([attempt_id.as_bytes().as_slice()], |row| {
                let sequence = nonnegative_u64(row.get(0)?)?;
                let key = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(1)?)?,
                    positive_u64(row.get(2)?)?,
                    fixed_bytes(row.get(3)?)?,
                    positive_u64(row.get(4)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let encrypted = ProviderEncryptedPayload::new(
                    fixed_bytes(row.get(5)?)?,
                    row.get(11)?,
                    nonnegative_u64(row.get(12)?)?,
                    fixed_bytes(row.get(13)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(ProviderJournalAppendRequest {
                    attempt_id,
                    fencing_token: attempt.fencing_token,
                    sequence,
                    event_kind: u8::try_from(row.get::<_, i64>(9)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    terminal: decode_bool(row.get(10)?)?,
                    call_digest_version: decode_call_digest_version(row.get(6)?)?,
                    profile_digest: fixed_bytes(row.get(7)?)?,
                    runtime_generation: positive_u64(row.get(8)?)?,
                    key,
                    encrypted,
                })
            })
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
        for (expected, row) in rows.iter().enumerate() {
            if row.sequence != expected as u64
                || row.profile_digest != attempt.profile_digest
                || row.runtime_generation != attempt.generation
                || row.call_digest_version != attempt.call_digest_version
                || row.key.runtime_authority_id() != attempt.runtime_authority_id
                || row.key.database_generation() != attempt.database_generation
            {
                return Err(ProviderExecutionError::JournalCorrupt);
            }
        }
        Ok(rows)
    }

}
impl SqliteProviderExecutionStore {
    fn load_terminal_pricing_binding_impl(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&connection, attempt_id)?;
        verify_current_runtime_lease(&connection, &attempt)?;
        if attempt.state == 6 {
            return Err(ProviderExecutionError::AttemptUncertain);
        }
        if !matches!(attempt.state, 3..=5) {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        ProviderTerminalPricingBinding::with_reservation(
            attempt.pricing_revision_digest,
            attempt.currency,
            attempt.requested_input_tokens,
            attempt.requested_output_tokens,
            attempt.max_cost_micros,
        )
    }

}
