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
    dispatch_attempt_id: DispatchAttemptId,
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
                    dispatch_attempt_id: attempt_id,
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
