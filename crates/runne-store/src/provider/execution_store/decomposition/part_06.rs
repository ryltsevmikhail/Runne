impl ProviderTerminalPersistence for SqliteProviderExecutionStore {
    fn commit_terminal(
        &self,
        request: &ProviderTerminalCommitRequest,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        validate_terminal_commit(request)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&transaction, request.attempt_id())?;
        verify_attempt_for_progress(
            &attempt,
            request.fencing_token(),
            request.runtime_generation(),
            *request.profile_digest(),
        )?;
        verify_current_runtime_lease(&transaction, &attempt)?;
        if terminal_commit_exists(&transaction, request)? {
            return Ok(ProviderTerminalCommitOutcome::Replayed);
        }
        if attempt.state == 6 {
            return Err(ProviderExecutionError::AttemptUncertain);
        }
        if attempt.state != 3 {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        if attempt.call_digest_version != request.call_digest_version() {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        ensure_known_journal_key(&transaction, request.key(), &attempt)?;
        verify_terminal_journal_record(&transaction, request)?;
        let reservations = load_reservations(&transaction, &attempt.provider_idempotency_key)?;
        let usage = request.usage();
        let usage_total = usage.total_tokens();
        if usage_total > reservations.token_amount
            || request.charge_micros() > reservations.cost_amount
            || request.currency() != attempt.currency
        {
            return Err(ProviderExecutionError::ReservationMismatch);
        }
        let now = unix_timestamp();
        transaction
            .execute(
                "INSERT INTO provider_accounting_settlements (
                    dispatch_attempt_id, pricing_revision_digest, input_tokens, output_tokens,
                    cached_input_tokens, reasoning_output_tokens, charge_micros, currency,
                    settlement_digest, committed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    request.attempt_id().as_bytes().as_slice(),
                    attempt.pricing_revision_digest.as_slice(),
                    execution_i64(usage.input_tokens())?,
                    execution_i64(usage.output_tokens())?,
                    execution_i64(usage.cached_input_tokens())?,
                    execution_i64(usage.reasoning_output_tokens())?,
                    execution_i64(request.charge_micros())?,
                    request.currency(),
                    request.settlement_digest().as_slice(),
                    now,
                ],
            )
            .map_err(|_| ProviderExecutionError::TerminalConflict)?;
        let next_state =
            if request.disposition() == runne_provider::ProviderTerminalDisposition::Completed {
                let encrypted_output = request
                    .encrypted_output()
                    .ok_or(ProviderExecutionError::TerminalConflict)?;
                insert_nonce(
                    &transaction,
                    request.key(),
                    encrypted_output.nonce(),
                    2,
                    request.attempt_id(),
                    None,
                )?;
                transaction
                    .execute(
                        "INSERT INTO provider_terminal_outbox (
                            outbox_id, dispatch_attempt_id, terminal_sequence, call_digest_version,
                            key_id, key_version, nonce, runtime_generation, profile_digest,
                            ciphertext, plaintext_len, plaintext_digest, settlement_digest,
                            application_idempotency_key, state, receipt_digest, created_at,
                            applied_at
                         ) VALUES (
                            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                            1, NULL, ?15, NULL
                         )",
                        params![
                            request.outbox_id().as_slice(),
                            request.attempt_id().as_bytes().as_slice(),
                            execution_i64(request.terminal_sequence())?,
                            encode_call_digest_version(request.call_digest_version()),
                            request.key().key_id().as_slice(),
                            execution_i64(request.key().key_version())?,
                            encrypted_output.nonce().as_slice(),
                            execution_i64(request.runtime_generation())?,
                            request.profile_digest().as_slice(),
                            encrypted_output.ciphertext(),
                            execution_i64(encrypted_output.plaintext_len())?,
                            encrypted_output.plaintext_digest().as_slice(),
                            request.settlement_digest().as_slice(),
                            request.application_idempotency_key(),
                            now,
                        ],
                    )
                    .map_err(|_| ProviderExecutionError::TerminalConflict)?;
                4_i64
            } else {
                5_i64
            };
        release_reservations(
            &transaction,
            &attempt.provider_idempotency_key,
            usage_total,
            request.charge_micros(),
            reservations,
            now,
        )?;
        let changed = transaction
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = ?3, settlement_digest = ?4
                 WHERE attempt_id = ?1 AND fencing_token = ?2 AND state = 3",
                params![
                    request.attempt_id().as_bytes().as_slice(),
                    execution_i64(request.fencing_token())?,
                    next_state,
                    request.settlement_digest().as_slice(),
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if changed != 1 {
            return Err(ProviderExecutionError::StaleGeneration);
        }
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        Ok(ProviderTerminalCommitOutcome::Committed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalKeyState {
    Active,
    Retired,
}

struct StoredJournalKey {
    binding: ProviderJournalKeyBinding,
}

fn load_journal_key_state(
    connection: &Connection,
    key: ProviderJournalKeyBinding,
) -> Result<Option<JournalKeyState>, ProviderExecutionError> {
    connection
        .query_row(
            "SELECT runtime_authority_id, database_generation, state
             FROM provider_journal_key_refs
             WHERE key_id = ?1 AND key_version = ?2",
            params![key.key_id().as_slice(), execution_i64(key.key_version())?,],
            |row| {
                let authority: [u8; 16] = fixed_bytes(row.get(0)?)?;
                let generation = positive_u64(row.get(1)?)?;
                if authority != key.runtime_authority_id()
                    || generation != key.database_generation()
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                match row.get::<_, i64>(2)? {
                    1 => Ok(JournalKeyState::Active),
                    2 => Ok(JournalKeyState::Retired),
                    _ => Err(rusqlite::Error::InvalidQuery),
                }
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn load_active_journal_key(
    connection: &Connection,
) -> Result<Option<StoredJournalKey>, ProviderExecutionError> {
    connection
        .query_row(
            "SELECT key_id, key_version, runtime_authority_id, database_generation
             FROM provider_journal_key_refs
             WHERE state = 1 AND active_slot = 1",
            [],
            |row| {
                let binding = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(0)?)?,
                    positive_u64(row.get(1)?)?,
                    fixed_bytes(row.get(2)?)?,
                    positive_u64(row.get(3)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(StoredJournalKey { binding })
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn ensure_journal_key_exists(
    connection: &Connection,
    key: ProviderJournalKeyBinding,
) -> Result<(), ProviderExecutionError> {
    if load_journal_key_state(connection, key)?.is_none() {
        return Err(ProviderExecutionError::JournalKeyUnavailable);
    }
    Ok(())
}

struct ExecutionAttempt {
    state: i64,
    fencing_token: u64,
    generation: u64,
    profile_digest: [u8; 32],
    pricing_revision_digest: [u8; 32],
    currency: String,
    provider_idempotency_key: String,
    call_digest_version: ProviderCallDigestVersion,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    requested_input_tokens: u64,
    requested_output_tokens: u64,
    max_cost_micros: u64,
}

fn load_execution_attempt(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
) -> Result<ExecutionAttempt, ProviderExecutionError> {
    connection
        .query_row(
            "SELECT dispatch.state, dispatch.fencing_token, admission.generation,
                    admission.profile_digest, admission.pricing_revision_digest,
                    admission.currency, admission.provider_idempotency_key,
                    prepared.call_digest_version, admission.runtime_authority_id,
                    admission.database_generation, admission.requested_input_tokens,
                    admission.requested_output_tokens, admission.max_cost_micros
             FROM provider_dispatch_attempts dispatch
             JOIN provider_execution_admissions admission
               ON admission.dispatch_attempt_id = dispatch.attempt_id
             JOIN provider_prepared_requests prepared
               ON prepared.call_id = admission.call_id
             WHERE dispatch.attempt_id = ?1",
            [attempt_id.as_bytes().as_slice()],
            |row| {
                Ok(ExecutionAttempt {
                    state: row.get(0)?,
                    fencing_token: positive_u64(row.get(1)?)?,
                    generation: positive_u64(row.get(2)?)?,
                    profile_digest: fixed_bytes(row.get(3)?)?,
                    pricing_revision_digest: fixed_bytes(row.get(4)?)?,
                    currency: row.get(5)?,
                    provider_idempotency_key: row.get(6)?,
                    call_digest_version: decode_call_digest_version(row.get(7)?)?,
                    runtime_authority_id: fixed_bytes(row.get(8)?)?,
                    database_generation: positive_u64(row.get(9)?)?,
                    requested_input_tokens: nonnegative_u64(row.get(10)?)?,
                    requested_output_tokens: positive_u64(row.get(11)?)?,
                    max_cost_micros: nonnegative_u64(row.get(12)?)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .ok_or(ProviderExecutionError::JournalCorrupt)
}
