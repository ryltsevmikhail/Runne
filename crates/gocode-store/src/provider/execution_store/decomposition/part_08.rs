fn verify_terminal_journal_record(
    connection: &Connection,
    request: &ProviderTerminalCommitRequest,
) -> Result<(), ProviderExecutionError> {
    let terminal = connection
        .query_row(
            "SELECT key_id, key_version, profile_digest, runtime_generation, terminal,
                    call_digest_version
             FROM provider_stream_journal
            WHERE dispatch_attempt_id = ?1 AND sequence = ?2",
            params![
                request.attempt_id().as_bytes().as_slice(),
                execution_i64(request.terminal_sequence())?,
            ],
            |row| {
                Ok((
                    fixed_bytes::<16>(row.get(0)?)?,
                    positive_u64(row.get(1)?)?,
                    fixed_bytes::<32>(row.get(2)?)?,
                    positive_u64(row.get(3)?)?,
                    decode_bool(row.get(4)?)?,
                    decode_call_digest_version(row.get(5)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .ok_or(ProviderExecutionError::TerminalConflict)?;
    if terminal.0 != request.key().key_id()
        || terminal.1 != request.key().key_version()
        || terminal.2 != *request.profile_digest()
        || terminal.3 != request.runtime_generation()
        || !terminal.4
        || terminal.5 != request.call_digest_version()
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Reservations {
    token_amount: u64,
    cost_amount: u64,
}

fn load_reservations(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Reservations, ProviderExecutionError> {
    let mut statement = connection
        .prepare(
            "SELECT dimension, amount, state, settled_amount, released_at
             FROM provider_budget_reservations
             WHERE provider_idempotency_key = ?1
             ORDER BY dimension",
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let rows = statement
        .query_map([idempotency_key], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                positive_u64(row.get(1)?)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if rows.len() != 2
        || rows[0].0 != 1
        || rows[1].0 != 2
        || rows
            .iter()
            .any(|row| row.2 != 1 || row.3.is_some() || row.4.is_some())
    {
        return Err(ProviderExecutionError::ReservationMismatch);
    }
    Ok(Reservations {
        token_amount: rows[0].1,
        cost_amount: rows[1].1,
    })
}

fn release_reservations(
    connection: &Connection,
    idempotency_key: &str,
    settled_tokens: u64,
    settled_cost: u64,
    reservations: Reservations,
    released_at: i64,
) -> Result<(), ProviderExecutionError> {
    for (dimension, settled_amount) in [(1_i64, settled_tokens), (2_i64, settled_cost)] {
        let changed = connection
            .execute(
                "UPDATE provider_budget_reservations
                 SET state = 2, settled_amount = ?3, released_at = ?4
                 WHERE provider_idempotency_key = ?1 AND dimension = ?2
                   AND state = 1 AND settled_amount IS NULL AND released_at IS NULL",
                params![
                    idempotency_key,
                    dimension,
                    execution_i64(settled_amount)?,
                    released_at,
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if changed != 1 {
            return Err(ProviderExecutionError::ReservationMismatch);
        }
    }
    let changed = connection
        .execute(
            "UPDATE provider_runtime_authority_state SET
                token_budget_reserved = token_budget_reserved - ?1,
                token_budget_settled = token_budget_settled + ?2,
                cost_budget_reserved_micros = cost_budget_reserved_micros - ?3,
                cost_budget_settled_micros = cost_budget_settled_micros + ?4
             WHERE id = 1 AND token_budget_reserved >= ?1
               AND cost_budget_reserved_micros >= ?3
               AND token_budget_settled + ?2
                   <= token_budget_limit - (token_budget_reserved - ?1)
               AND cost_budget_settled_micros + ?4
                   <= cost_budget_limit_micros - (cost_budget_reserved_micros - ?3)",
            params![
                execution_i64(reservations.token_amount)?,
                execution_i64(settled_tokens)?,
                execution_i64(reservations.cost_amount)?,
                execution_i64(settled_cost)?,
            ],
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if changed != 1 {
        return Err(ProviderExecutionError::ReservationMismatch);
    }
    Ok(())
}

fn terminal_commit_exists(
    connection: &Connection,
    request: &ProviderTerminalCommitRequest,
) -> Result<bool, ProviderExecutionError> {
    if request.disposition() != gocode_provider::ProviderTerminalDisposition::Completed {
        return terminal_non_delivery_commit_exists(connection, request);
    }
    let encrypted_output = request
        .encrypted_output()
        .ok_or(ProviderExecutionError::TerminalConflict)?;
    let existing = connection
        .query_row(
            "SELECT outbox.outbox_id, outbox.dispatch_attempt_id,
                    outbox.terminal_sequence, outbox.call_digest_version,
                    outbox.key_id, outbox.key_version, keys.runtime_authority_id,
                    keys.database_generation, outbox.nonce, outbox.runtime_generation,
                    outbox.profile_digest, outbox.ciphertext, outbox.plaintext_len,
                    outbox.plaintext_digest, outbox.settlement_digest,
                    outbox.application_idempotency_key,
                    accounting.input_tokens, accounting.output_tokens,
                    accounting.cached_input_tokens, accounting.reasoning_output_tokens,
                    accounting.charge_micros, accounting.currency,
                    accounting.pricing_revision_digest
             FROM provider_terminal_outbox outbox
             JOIN provider_journal_key_refs keys
               ON keys.key_id = outbox.key_id AND keys.key_version = outbox.key_version
             JOIN provider_accounting_settlements accounting
               ON accounting.dispatch_attempt_id = outbox.dispatch_attempt_id
            WHERE outbox.outbox_id = ?1 OR outbox.dispatch_attempt_id = ?2",
            params![
                request.outbox_id().as_slice(),
                request.attempt_id().as_bytes().as_slice(),
            ],
            |row| {
                let key = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(4)?)?,
                    positive_u64(row.get(5)?)?,
                    fixed_bytes(row.get(6)?)?,
                    positive_u64(row.get(7)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let encrypted = ProviderEncryptedPayload::new(
                    fixed_bytes(row.get(8)?)?,
                    row.get(11)?,
                    nonnegative_u64(row.get(12)?)?,
                    fixed_bytes(row.get(13)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let usage = gocode_provider::ProviderUsage::new(
                    nonnegative_u64(row.get(16)?)?,
                    nonnegative_u64(row.get(17)?)?,
                    nonnegative_u64(row.get(18)?)?,
                    nonnegative_u64(row.get(19)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok((
                    fixed_bytes::<16>(row.get(0)?)?,
                    DispatchAttemptId::from_bytes(fixed_bytes(row.get(1)?)?),
                    nonnegative_u64(row.get(2)?)?,
                    decode_call_digest_version(row.get(3)?)?,
                    key,
                    encrypted,
                    positive_u64(row.get(9)?)?,
                    fixed_bytes::<32>(row.get(10)?)?,
                    fixed_bytes::<32>(row.get(14)?)?,
                    row.get::<_, String>(15)?,
                    usage,
                    nonnegative_u64(row.get(20)?)?,
                    row.get::<_, String>(21)?,
                    fixed_bytes::<32>(row.get(22)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let Some(existing) = existing else {
        return Ok(false);
    };
    let attempt = load_execution_attempt(connection, request.attempt_id())?;
    if existing.0 != *request.outbox_id()
        || existing.1 != request.attempt_id()
        || existing.2 != request.terminal_sequence()
        || existing.3 != request.call_digest_version()
        || existing.4 != request.key()
        || existing.5.plaintext_len() != encrypted_output.plaintext_len()
        || existing.5.plaintext_digest() != encrypted_output.plaintext_digest()
        || existing.6 != request.runtime_generation()
        || existing.7 != *request.profile_digest()
        || existing.8 != *request.settlement_digest()
        || existing.9 != request.application_idempotency_key()
        || existing.10 != request.usage()
        || existing.11 != request.charge_micros()
        || existing.12 != request.currency()
        || existing.13 != attempt.pricing_revision_digest
        || !matches!(attempt.state, 4 | 5)
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(true)
}
