fn verify_attempt_for_progress(
    attempt: &ExecutionAttempt,
    fencing_token: u64,
    generation: u64,
    profile_digest: [u8; 32],
) -> Result<(), ProviderExecutionError> {
    if attempt.fencing_token != fencing_token || attempt.generation != generation {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    if attempt.profile_digest != profile_digest {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(())
}
fn verify_current_runtime_lease(
    connection: &Connection,
    attempt: &ExecutionAttempt,
) -> Result<(), ProviderExecutionError> {
    let current = connection
        .query_row(
            "SELECT runtime_authority_id, database_generation,
                    expected_generation, lease_generation,
                    expected_fencing_token, lease_fencing_token,
                    profile_digest, pricing_revision_digest, active
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| {
                Ok((
                    fixed_bytes::<16>(row.get(0)?)?,
                    positive_u64(row.get(1)?)?,
                    positive_u64(row.get(2)?)?,
                    positive_u64(row.get(3)?)?,
                    positive_u64(row.get(4)?)?,
                    positive_u64(row.get(5)?)?,
                    fixed_bytes::<32>(row.get(6)?)?,
                    fixed_bytes::<32>(row.get(7)?)?,
                    decode_bool(row.get(8)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?
        .ok_or(ProviderExecutionError::StaleGeneration)?;
    if !current.8
        || current.0 != attempt.runtime_authority_id
        || current.1 != attempt.database_generation
        || current.2 != attempt.generation
        || current.3 != attempt.generation
        || current.4 != attempt.fencing_token
        || current.5 != attempt.fencing_token
        || current.6 != attempt.profile_digest
        || current.7 != attempt.pricing_revision_digest
    {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    Ok(())
}

fn ensure_active_journal_key(
    connection: &Connection,
    key: ProviderJournalKeyBinding,
    attempt: &ExecutionAttempt,
) -> Result<(), ProviderExecutionError> {
    if key.runtime_authority_id() != attempt.runtime_authority_id
        || key.database_generation() != attempt.database_generation
        || load_journal_key_state(connection, key)? != Some(JournalKeyState::Active)
    {
        return Err(ProviderExecutionError::JournalKeyUnavailable);
    }
    Ok(())
}

fn ensure_known_journal_key(
    connection: &Connection,
    key: ProviderJournalKeyBinding,
    attempt: &ExecutionAttempt,
) -> Result<(), ProviderExecutionError> {
    if key.runtime_authority_id() != attempt.runtime_authority_id
        || key.database_generation() != attempt.database_generation
        || load_journal_key_state(connection, key)?.is_none()
    {
        return Err(ProviderExecutionError::JournalKeyUnavailable);
    }
    Ok(())
}

fn validate_journal_append(
    request: &ProviderJournalAppendRequest,
) -> Result<(), ProviderExecutionError> {
    if request.fencing_token == 0
        || request.runtime_generation == 0
        || !(1..=6).contains(&request.event_kind)
        || request.encrypted.ciphertext().len() > 2_097_152
        || (request.terminal && request.event_kind != 5)
        || (!request.terminal && request.event_kind == 5)
    {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(())
}

fn validate_poll_request(request: &ProviderPollRequest) -> Result<(), ProviderExecutionError> {
    if request.fencing_token == 0 || request.runtime_generation == 0 {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    Ok(())
}

fn load_encrypted_event(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
    sequence: u64,
) -> Result<Option<ProviderJournalAppendRequest>, ProviderExecutionError> {
    let attempt = load_execution_attempt(connection, attempt_id)?;
    connection
        .query_row(
            "SELECT journal.key_id, journal.key_version, keys.runtime_authority_id,
                    keys.database_generation, journal.nonce, journal.call_digest_version,
                    journal.profile_digest, journal.runtime_generation, journal.event_kind,
                    journal.terminal, journal.ciphertext, journal.plaintext_len,
                    journal.plaintext_digest
             FROM provider_stream_journal journal
             JOIN provider_journal_key_refs keys
               ON keys.key_id = journal.key_id AND keys.key_version = journal.key_version
             WHERE journal.dispatch_attempt_id = ?1 AND journal.sequence = ?2",
            params![attempt_id.as_bytes().as_slice(), execution_i64(sequence)?,],
            |row| {
                let key = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(0)?)?,
                    positive_u64(row.get(1)?)?,
                    fixed_bytes(row.get(2)?)?,
                    positive_u64(row.get(3)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let encrypted = ProviderEncryptedPayload::new(
                    fixed_bytes(row.get(4)?)?,
                    row.get(10)?,
                    nonnegative_u64(row.get(11)?)?,
                    fixed_bytes(row.get(12)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(ProviderJournalAppendRequest {
                    attempt_id,
                    fencing_token: attempt.fencing_token,
                    sequence,
                    event_kind: u8::try_from(row.get::<_, i64>(8)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    terminal: decode_bool(row.get(9)?)?,
                    call_digest_version: decode_call_digest_version(row.get(5)?)?,
                    profile_digest: fixed_bytes(row.get(6)?)?,
                    runtime_generation: positive_u64(row.get(7)?)?,
                    key,
                    encrypted,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn next_journal_sequence(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
) -> Result<u64, ProviderExecutionError> {
    let maximum: Option<i64> = connection
        .query_row(
            "SELECT MAX(sequence) FROM provider_stream_journal
             WHERE dispatch_attempt_id = ?1",
            [attempt_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    match maximum {
        Some(maximum) => nonnegative_u64(maximum)
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?
            .checked_add(1)
            .ok_or(ProviderExecutionError::SequenceMismatch),
        None => Ok(0),
    }
}

fn insert_nonce(
    connection: &Connection,
    key: ProviderJournalKeyBinding,
    nonce: &[u8; 12],
    purpose: i64,
    attempt_id: DispatchAttemptId,
    sequence: Option<u64>,
) -> Result<(), ProviderExecutionError> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM provider_encryption_nonces
                WHERE key_id = ?1 AND key_version = ?2 AND nonce = ?3
             )",
            params![
                key.key_id().as_slice(),
                execution_i64(key.key_version())?,
                nonce.as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if exists {
        return Err(ProviderExecutionError::NonceReuse);
    }
    connection
        .execute(
            "INSERT INTO provider_encryption_nonces (
                key_id, key_version, nonce, purpose, dispatch_attempt_id, sequence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                key.key_id().as_slice(),
                execution_i64(key.key_version())?,
                nonce.as_slice(),
                purpose,
                attempt_id.as_bytes().as_slice(),
                sequence.map(execution_i64).transpose()?,
            ],
        )
        .map_err(|_| ProviderExecutionError::NonceReuse)?;
    Ok(())
}

fn validate_terminal_commit(
    request: &ProviderTerminalCommitRequest,
) -> Result<(), ProviderExecutionError> {
    let completed =
        request.disposition() == gocode_provider::ProviderTerminalDisposition::Completed;
    if request.outbox_id() == &[0; 16]
        || request.fencing_token() == 0
        || request.runtime_generation() == 0
        || request.settlement_digest() == &[0; 32]
        || request.currency().len() != 3
        || !request
            .currency()
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
        || request.application_idempotency_key().is_empty()
        || request.application_idempotency_key().len() > 256
        || request
            .application_idempotency_key()
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || matches!(
            request.disposition(),
            gocode_provider::ProviderTerminalDisposition::CancelledUncertain
        )
        || (completed && request.usage_unavailable())
        || completed != request.encrypted_output().is_some()
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(())
}
