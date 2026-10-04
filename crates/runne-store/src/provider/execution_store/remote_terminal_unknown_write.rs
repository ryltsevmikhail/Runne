impl SqliteProviderExecutionStore {
    fn commit_unknown_terminal_impl(
        &self,
        selector: &ProviderTerminalUnknownSelector,
        authenticate: &dyn ProviderUnknownTerminalAuthenticator,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let proof_state = self
            .online_effect_proof
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let proof = proof_state
            .as_ref()
            .ok_or(ProviderExecutionError::TerminalConflict)?;
        let attempt = load_execution_attempt(&transaction, selector.attempt_id())?;
        if attempt.fencing_token != selector.fencing_token() || attempt.profile_digest == [0; 32] {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let (snapshot, rows) = crate::store::test_support_diagnostics::on_error(
            "unknown.snapshot_load",
            load_unknown_snapshot(&transaction, selector, proof),
        )?;
        let authorization = crate::store::test_support_diagnostics::on_error(
            "unknown.runtime_authentication",
            authenticate.authenticate(&snapshot),
        )?;
        verify_unknown_authorization(selector, &authorization)?;
        let existing = unknown_receipt_exists(&transaction, selector.attempt_id())?;
        if existing {
            verify_existing_unknown_commitment(&transaction, selector, &authorization)?;
            return Ok(ProviderTerminalCommitOutcome::Replayed);
        }
        if !matches!(attempt.state, 3 | 6) {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        ensure_no_known_terminal(&transaction, selector.attempt_id())?;
        if rows
            .reservations
            .iter()
            .any(|reserve| !reserve.held || reserve.settled_amount.is_some())
        {
            return Err(ProviderExecutionError::ReservationMismatch);
        }
        crate::store::test_support_diagnostics::on_error(
            "unknown.persist",
            persist_unknown_terminal(&transaction, &attempt, selector, &rows, &authorization),
        )?;
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        Ok(ProviderTerminalCommitOutcome::Committed)
    }

    fn replay_unknown_terminal_impl(
        &self,
        selector: &ProviderTerminalUnknownSelector,
        authenticate: &dyn ProviderUnknownTerminalAuthenticator,
    ) -> Result<Option<ProviderTerminalCommitOutcome>, ProviderExecutionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if !unknown_receipt_exists(&transaction, selector.attempt_id())? {
            return Ok(None);
        }
        let proof_state = self
            .online_effect_proof
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let proof = proof_state
            .as_ref()
            .ok_or(ProviderExecutionError::TerminalConflict)?;
        let (snapshot, _) = load_unknown_snapshot(&transaction, selector, proof)?;
        let authorization = authenticate.authenticate(&snapshot)?;
        verify_unknown_authorization(selector, &authorization)?;
        verify_existing_unknown_commitment(&transaction, selector, &authorization)?;
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        Ok(Some(ProviderTerminalCommitOutcome::Replayed))
    }
}

fn verify_unknown_authorization(
    selector: &ProviderTerminalUnknownSelector,
    authorization: &ProviderUnknownTerminalAuthorization,
) -> Result<(), ProviderExecutionError> {
    if authorization.attempt_id() != selector.attempt_id()
        || authorization.terminal_sequence() != selector.terminal_sequence()
        || authorization.commitment() == &[0; 32]
        || authorization.journal_digest() == &[0; 32]
        || authorization.source_binding_digest() == &[0; 32]
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(())
}

fn unknown_receipt_exists(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
) -> Result<bool, ProviderExecutionError> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_unknown_terminal_receipts WHERE dispatch_attempt_id=?1)",
        [attempt_id.as_bytes().as_slice()],
        |row| row.get(0),
    ).map_err(|_| ProviderExecutionError::StoreUnavailable)
}

fn ensure_no_known_terminal(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
) -> Result<(), ProviderExecutionError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1)
             OR EXISTS(SELECT 1 FROM provider_terminal_dispositions WHERE dispatch_attempt_id=?1)",
        [attempt_id.as_bytes().as_slice()],
        |row| row.get(0),
    ).map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if exists {
        Err(ProviderExecutionError::TerminalConflict)
    } else {
        Ok(())
    }
}

fn verify_existing_unknown_commitment(
    connection: &Connection,
    selector: &ProviderTerminalUnknownSelector,
    authorization: &ProviderUnknownTerminalAuthorization,
) -> Result<(), ProviderExecutionError> {
    let row = connection
        .query_row(
            "SELECT unknown_commitment,source_binding_digest,journal_digest,accounting_reason,
                    terminal_disposition,usage_present,input_tokens,output_tokens,
                    cached_input_tokens,reasoning_output_tokens,output_key_id,output_key_version,
                    output_nonce,output_ciphertext,output_plaintext_len,output_digest,outbox_id,
                    application_idempotency_key
             FROM provider_unknown_terminal_receipts
             WHERE dispatch_attempt_id=?1 AND terminal_sequence=?2 AND fencing_token=?3",
            params![
                selector.attempt_id().as_bytes().as_slice(),
                execution_i64(selector.terminal_sequence())?,
                execution_i64(selector.fencing_token())?
            ],
            |row| {
                Ok(UnknownStoredReceipt {
                    commitment: row.get(0)?,
                    source_digest: row.get(1)?,
                    journal_digest: row.get(2)?,
                    reason: row.get(3)?,
                    disposition: row.get(4)?,
                    usage_present: row.get(5)?,
                    input: row.get(6)?,
                    output: row.get(7)?,
                    cached: row.get(8)?,
                    reasoning: row.get(9)?,
                    output_key: row.get(10)?,
                    output_key_version: row.get(11)?,
                    output_nonce: row.get(12)?,
                    output_ciphertext: row.get(13)?,
                    output_len: row.get(14)?,
                    output_digest: row.get(15)?,
                    outbox_id: row.get(16)?,
                    application_key: row.get(17)?,
                })
            },
        )
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let usage_matches = match authorization.usage() {
        None => {
            row.usage_present == 0
                && row.input.is_none()
                && row.output.is_none()
                && row.cached.is_none()
                && row.reasoning.is_none()
        }
        Some(usage) => {
            row.usage_present == 1
                && row.input == Some(execution_i64(usage.input_tokens())?)
                && row.output == Some(execution_i64(usage.output_tokens())?)
                && row.cached == Some(execution_i64(usage.cached_input_tokens())?)
                && row.reasoning == Some(execution_i64(usage.reasoning_output_tokens())?)
        }
    };
    let output_matches = match authorization.encrypted_output() {
        Some(payload) => {
            row.output_key.is_some()
                && row.output_key_version.is_some()
                && row.output_nonce.as_deref() == Some(payload.nonce().as_slice())
                && row.output_ciphertext.as_deref() == Some(payload.ciphertext())
                && row.output_len == Some(execution_i64(payload.plaintext_len())?)
                && row.output_digest.as_deref() == Some(payload.plaintext_digest().as_slice())
        }
        None => {
            row.output_key.is_none()
                && row.output_key_version.is_none()
                && row.output_nonce.is_none()
                && row.output_ciphertext.is_none()
                && row.output_len.is_none()
                && row.output_digest.is_none()
                && row.outbox_id.is_none()
                && row.application_key.is_none()
        }
    };
    let outbox_matches = match authorization.published_outbox_id() {
        Some(expected_id) => {
            row.outbox_id.as_deref() == Some(expected_id.as_slice())
                && row.application_key.as_deref() == authorization.application_idempotency_key()
        }
        None => row.outbox_id.is_none() && row.application_key.is_none(),
    };
    if unknown_fixed_bytes::<32>(row.commitment)? != *authorization.commitment()
        || unknown_fixed_bytes::<32>(row.source_digest)? != *authorization.source_binding_digest()
        || unknown_fixed_bytes::<32>(row.journal_digest)? != *authorization.journal_digest()
        || row.reason != unknown_reason_code(authorization.reason())
        || row.disposition != unknown_disposition_code(authorization.disposition())?
        || !usage_matches
        || !output_matches
        || !outbox_matches
    {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(())
}

struct UnknownStoredReceipt {
    commitment: Vec<u8>,
    source_digest: Vec<u8>,
    journal_digest: Vec<u8>,
    reason: i64,
    disposition: i64,
    usage_present: i64,
    input: Option<i64>,
    output: Option<i64>,
    cached: Option<i64>,
    reasoning: Option<i64>,
    output_key: Option<Vec<u8>>,
    output_key_version: Option<i64>,
    output_nonce: Option<Vec<u8>>,
    output_ciphertext: Option<Vec<u8>>,
    output_len: Option<i64>,
    output_digest: Option<Vec<u8>>,
    outbox_id: Option<Vec<u8>>,
    application_key: Option<String>,
}

include!("remote_terminal_unknown_persist.rs");
