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
        secondary_profile_grant::verify_secondary_attempt_binding(
            &transaction,
            request.attempt_id(),
            *request.profile_digest(),
            attempt.pricing_revision_digest,
            false,
        )?;
        verify_current_runtime_lease(&transaction, &attempt)?;
        if terminal_commit_exists(&transaction, request)? {
            verify_terminal_disposition_marker(&transaction, request)?;
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
        transaction.execute(
            "INSERT INTO provider_terminal_dispositions(dispatch_attempt_id,disposition) VALUES(?1,?2)",
            params![
                request.attempt_id().as_bytes().as_slice(),
                terminal_disposition_code(request.disposition()),
            ],
        ).map_err(|_| ProviderExecutionError::TerminalConflict)?;
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
        #[cfg(feature = "test-support")]
        crate::store::commit_gate::note_kill_boundary("b5_pre_settlement_commit");
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        Ok(ProviderTerminalCommitOutcome::Committed)
    }

    fn commit_unknown_terminal(
        &self,
        selector: &ProviderTerminalUnknownSelector,
        authenticate: &dyn runne_runtime::provider_execution::ProviderUnknownTerminalAuthenticator,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        self.commit_unknown_terminal_impl(selector, authenticate)
    }

    fn replay_unknown_terminal(
        &self,
        selector: &ProviderTerminalUnknownSelector,
        authenticate: &dyn runne_runtime::provider_execution::ProviderUnknownTerminalAuthenticator,
    ) -> Result<Option<ProviderTerminalCommitOutcome>, ProviderExecutionError> {
        self.replay_unknown_terminal_impl(selector, authenticate)
    }
}

fn terminal_disposition_code(disposition: runne_provider::ProviderTerminalDisposition) -> i64 {
    match disposition {
        runne_provider::ProviderTerminalDisposition::Completed => 1,
        runne_provider::ProviderTerminalDisposition::RemoteFailed => 2,
        runne_provider::ProviderTerminalDisposition::RemoteIncomplete => 3,
        runne_provider::ProviderTerminalDisposition::CancelledUncertain => 4,
    }
}

fn verify_terminal_disposition_marker(
    transaction: &Transaction<'_>,
    request: &ProviderTerminalCommitRequest,
) -> Result<(), ProviderExecutionError> {
    let marker: Option<i64> = transaction
        .query_row(
            "SELECT disposition FROM provider_terminal_dispositions WHERE dispatch_attempt_id=?1",
            [request.attempt_id().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if marker.is_some_and(|value| value != terminal_disposition_code(request.disposition())) {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(())
}
