fn terminal_non_delivery_commit_exists(
    connection: &Connection,
    request: &ProviderTerminalCommitRequest,
) -> Result<bool, ProviderExecutionError> {
    let existing = connection
        .query_row(
            "SELECT dispatch.state, dispatch.settlement_digest,
                    accounting.input_tokens, accounting.output_tokens,
                    accounting.cached_input_tokens, accounting.reasoning_output_tokens,
                    accounting.charge_micros, accounting.currency,
                    accounting.pricing_revision_digest,
                    EXISTS(
                        SELECT 1 FROM provider_terminal_outbox outbox
                        WHERE outbox.dispatch_attempt_id = dispatch.attempt_id
                    )
             FROM provider_dispatch_attempts dispatch
             JOIN provider_accounting_settlements accounting
               ON accounting.dispatch_attempt_id = dispatch.attempt_id
             WHERE dispatch.attempt_id = ?1",
            [request.attempt_id().as_bytes().as_slice()],
            |row| {
                let usage = gocode_provider::ProviderUsage::new(
                    nonnegative_u64(row.get(2)?)?,
                    nonnegative_u64(row.get(3)?)?,
                    nonnegative_u64(row.get(4)?)?,
                    nonnegative_u64(row.get(5)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok((
                    row.get::<_, i64>(0)?,
                    fixed_bytes::<32>(row.get(1)?)?,
                    usage,
                    nonnegative_u64(row.get(6)?)?,
                    row.get::<_, String>(7)?,
                    fixed_bytes::<32>(row.get(8)?)?,
                    decode_bool(row.get(9)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let Some(existing) = existing else {
        return Ok(false);
    };
    let attempt = load_execution_attempt(connection, request.attempt_id())?;
    if existing.0 != 5
        || existing.1 != *request.settlement_digest()
        || existing.2 != request.usage()
        || existing.3 != request.charge_micros()
        || existing.4 != request.currency()
        || existing.5 != attempt.pricing_revision_digest
        || existing.6
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(true)
}

fn execution_i64(value: u64) -> Result<i64, ProviderExecutionError> {
    i64::try_from(value).map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn encode_call_digest_version(version: ProviderCallDigestVersion) -> i64 {
    match version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    }
}

fn decode_call_digest_version(value: i64) -> rusqlite::Result<ProviderCallDigestVersion> {
    match value {
        1 => Ok(ProviderCallDigestVersion::V1),
        2 => Ok(ProviderCallDigestVersion::V2),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn install_runtime_authority_in_transaction(
    transaction: &Transaction<'_>,
    config: &ProviderRuntimeAuthorityConfig,
    now: i64,
    allow_generation_advance: bool,
) -> Result<(), ProviderAdmissionError> {
    match load_runtime_authority(transaction)? {
        None => insert_runtime_authority(transaction, config, 1, now),
        Some(existing) => {
            existing.validate_renewal(config, allow_generation_advance)?;
            replace_runtime_authority(transaction, config, &existing, now)
        }
    }
}

fn advance_worker_lease_in_transaction(
    transaction: &Transaction<'_>,
    generation: u64,
    fencing_token: u64,
) -> Result<(), ProviderAdmissionError> {
    let generation_i64 = as_i64(generation)?;
    let fencing_token_i64 = as_i64(fencing_token)?;
    let existing =
        load_runtime_authority(transaction)?.ok_or(ProviderAdmissionError::StaleFencingToken)?;
    let changed = transaction
        .execute(
            "UPDATE provider_runtime_authority_state
             SET lease_generation = ?1, lease_fencing_token = ?2
             WHERE id = 1 AND active = 1 AND (
                    ?1 > lease_generation OR
                    (?1 = lease_generation AND ?2 = lease_fencing_token)
               )",
            params![generation_i64, fencing_token_i64],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if changed != 1 {
        return Err(ProviderAdmissionError::StaleFencingToken);
    }
    if existing.lease_generation != generation || existing.lease_fencing_token != fencing_token {
        transaction
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = 6
                 WHERE state IN (1, 3) AND EXISTS (
                    SELECT 1 FROM provider_execution_admissions admission
                    WHERE admission.dispatch_attempt_id = provider_dispatch_attempts.attempt_id
                      AND (
                        admission.generation != ?1 OR
                        admission.fencing_token != ?2
                      )
                 )",
                params![generation_i64, fencing_token_i64],
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    }
    Ok(())
}
fn load_runtime_authority(
    transaction: &Transaction<'_>,
) -> Result<Option<RuntimeAuthorityState>, ProviderAdmissionError> {
    transaction
        .query_row(
            "SELECT runtime_authority_id, database_generation, principal_id, owner_id, scope,
                    expected_generation, lease_generation, expected_fencing_token,
                    lease_fencing_token, capability_grant_id, capability_revision,
                    capability_allowed, capability_expires_at, capability_revocation_epoch,
                    capability_revocation_observed,
                    approval_id, approval_revision, approval_allowed, approval_expires_at,
                    approval_revocation_epoch, approval_revocation_observed, profile_digest,
                    pricing_revision_digest,
                    activation_binding_kind, activation_binding_digest,
                    token_budget_limit, token_budget_reserved, token_budget_settled,
                    cost_budget_limit_micros, cost_budget_reserved_micros,
                    cost_budget_settled_micros, authority_ttl_seconds, state_revision, active
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| {
                Ok(RuntimeAuthorityState {
                    runtime_authority_id: fixed_bytes(row.get(0)?)?,
                    database_generation: positive_u64(row.get(1)?)?,
                    principal_id: row.get(2)?,
                    owner_id: row.get(3)?,
                    scope: row.get(4)?,
                    expected_generation: positive_u64(row.get(5)?)?,
                    lease_generation: positive_u64(row.get(6)?)?,
                    expected_fencing_token: positive_u64(row.get(7)?)?,
                    lease_fencing_token: positive_u64(row.get(8)?)?,
                    capability_grant_id: row.get(9)?,
                    capability_revision: positive_u64(row.get(10)?)?,
                    capability_allowed: decode_bool(row.get(11)?)?,
                    capability_expires_at: row.get(12)?,
                    capability_revocation_epoch: nonnegative_u64(row.get(13)?)?,
                    capability_revocation_observed: decode_bool(row.get(14)?)?,
                    approval_id: row.get(15)?,
                    approval_revision: positive_u64(row.get(16)?)?,
                    approval_allowed: decode_bool(row.get(17)?)?,
                    approval_expires_at: row.get(18)?,
                    approval_revocation_epoch: nonnegative_u64(row.get(19)?)?,
                    approval_revocation_observed: decode_bool(row.get(20)?)?,
                    profile_digest: fixed_bytes(row.get(21)?)?,
                    pricing_revision_digest: fixed_bytes(row.get(22)?)?,
                    activation_binding_kind: binding_kind(row.get::<_, String>(23)?.as_str())?,
                    activation_binding_digest: fixed_bytes(row.get(24)?)?,
                    token_budget_limit: nonnegative_u64(row.get(25)?)?,
                    token_budget_reserved: nonnegative_u64(row.get(26)?)?,
                    token_budget_settled: nonnegative_u64(row.get(27)?)?,
                    cost_budget_limit_micros: nonnegative_u64(row.get(28)?)?,
                    cost_budget_reserved_micros: nonnegative_u64(row.get(29)?)?,
                    cost_budget_settled_micros: nonnegative_u64(row.get(30)?)?,
                    authority_ttl_seconds: positive_u64(row.get(31)?)?,
                    state_revision: positive_u64(row.get(32)?)?,
                    active: decode_bool(row.get(33)?)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}

fn insert_runtime_authority(
    transaction: &Transaction<'_>,
    config: &ProviderRuntimeAuthorityConfig,
    state_revision: u64,
    now: i64,
) -> Result<(), ProviderAdmissionError> {
    let expires_at = now
        .checked_add(
            i64::try_from(config.lease_ttl_seconds)
                .map_err(|_| ProviderAdmissionError::RepositoryFailure)?,
        )
        .ok_or(ProviderAdmissionError::RepositoryFailure)?;
    transaction
        .execute(
            "INSERT INTO provider_runtime_authority_state (
                id, runtime_authority_id, database_generation, principal_id, owner_id, scope,
                expected_generation, lease_generation, expected_fencing_token,
                lease_fencing_token, capability_grant_id, capability_revision,
                capability_allowed, capability_expires_at, capability_revocation_epoch,
                capability_revocation_observed,
                approval_id, approval_revision, approval_allowed, approval_expires_at,
                approval_revocation_epoch, approval_revocation_observed, profile_digest,
                pricing_revision_digest,
                activation_binding_kind, activation_binding_digest,
                token_budget_limit, token_budget_reserved, token_budget_settled,
                cost_budget_limit_micros, cost_budget_reserved_micros,
                cost_budget_settled_micros, authority_ttl_seconds, state_revision, active
             ) VALUES (
                1, ?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?7, ?8, ?9, ?10, ?11, ?12, 0, ?13,
                ?14, ?15, ?16, ?17, 0, ?18, ?19, ?20, ?21, ?22, 0, 0, ?23, 0, 0, ?24, ?25, 1
             )",
            params![
                config.runtime_authority_id.as_slice(),
                as_i64(config.database_generation)?,
                config.principal_id,
                config.owner_id,
                config.scope,
                as_i64(config.generation)?,
                as_i64(config.fencing_token)?,
                config.capability_grant_id,
                as_i64(config.capability_revision)?,
                i64::from(config.capability_allowed),
                expires_at,
                as_i64(config.capability_revocation_epoch)?,
                config.approval_id,
                as_i64(config.approval_revision)?,
                i64::from(config.approval_allowed),
                expires_at,
                as_i64(config.approval_revocation_epoch)?,
                config.profile_digest.as_slice(),
                config.pricing_revision_digest.as_slice(),
                config.activation_binding_kind.code(),
                config.activation_binding_digest.as_slice(),
                as_i64(config.token_budget_limit)?,
                as_i64(config.cost_budget_limit_micros)?,
                as_i64(config.authority_ttl_seconds)?,
                as_i64(state_revision)?,
            ],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    Ok(())
}
