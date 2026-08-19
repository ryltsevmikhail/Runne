fn replace_runtime_authority(
    transaction: &Transaction<'_>,
    config: &ProviderRuntimeAuthorityConfig,
    existing: &RuntimeAuthorityState,
    now: i64,
) -> Result<(), ProviderAdmissionError> {
    let expires_at = now
        .checked_add(
            i64::try_from(config.lease_ttl_seconds)
                .map_err(|_| ProviderAdmissionError::RepositoryFailure)?,
        )
        .ok_or(ProviderAdmissionError::RepositoryFailure)?;
    let changed = transaction
        .execute(
            "UPDATE provider_runtime_authority_state SET
                principal_id = ?1, owner_id = ?2, scope = ?3,
                expected_generation = ?4,
                expected_fencing_token = ?5,
                capability_grant_id = ?6, capability_revision = ?7, capability_allowed = ?8,
                capability_expires_at = ?9, capability_revocation_epoch = ?10,
                capability_revocation_observed = ?11, approval_id = ?12,
                approval_revision = ?13, approval_allowed = ?14, approval_expires_at = ?15,
                approval_revocation_epoch = ?16, approval_revocation_observed = ?17,
                profile_digest = ?18, pricing_revision_digest = ?19,
                activation_binding_kind = ?20, activation_binding_digest = ?21,
                token_budget_limit = ?22, cost_budget_limit_micros = ?23,
                authority_ttl_seconds = ?24, state_revision = ?25, active = 1
             WHERE id = 1 AND runtime_authority_id = ?26 AND database_generation = ?27
               AND token_budget_limit = ?22 AND cost_budget_limit_micros = ?23",
            params![
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
                i64::from(existing.capability_revocation_observed_on_renewal(config)),
                config.approval_id,
                as_i64(config.approval_revision)?,
                i64::from(config.approval_allowed),
                expires_at,
                as_i64(config.approval_revocation_epoch)?,
                i64::from(existing.approval_revocation_observed_on_renewal(config)),
                config.profile_digest.as_slice(),
                config.pricing_revision_digest.as_slice(),
                config.activation_binding_kind.code(),
                config.activation_binding_digest.as_slice(),
                as_i64(config.token_budget_limit)?,
                as_i64(config.cost_budget_limit_micros)?,
                as_i64(config.authority_ttl_seconds)?,
                as_i64(
                    existing
                        .state_revision
                        .checked_add(1)
                        .ok_or(ProviderAdmissionError::RepositoryFailure,)?
                )?,
                config.runtime_authority_id.as_slice(),
                as_i64(config.database_generation)?,
            ],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if changed != 1 {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    Ok(())
}

fn verify_runtime_authority(
    state: &RuntimeAuthorityState,
    request: &ProviderAuthorityIssueRequest,
    now: i64,
) -> Result<(), ProviderAdmissionError> {
    if !state.active || state.principal_id != request.principal_id {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    if state.expected_generation != state.lease_generation
        || state.expected_fencing_token != state.lease_fencing_token
    {
        return Err(ProviderAdmissionError::StaleFencingToken);
    }
    if !state.capability_allowed {
        return Err(if state.capability_revocation_observed {
            ProviderAdmissionError::CapabilityRevoked
        } else {
            ProviderAdmissionError::CapabilityDenied
        });
    }
    if state.capability_expires_at <= now {
        return Err(ProviderAdmissionError::CapabilityExpired);
    }
    if !state.approval_allowed {
        return Err(if state.approval_revocation_observed {
            ProviderAdmissionError::ApprovalRevoked
        } else {
            ProviderAdmissionError::ApprovalDenied
        });
    }
    if state.approval_expires_at <= now {
        return Err(ProviderAdmissionError::ApprovalExpired);
    }
    if state.activation_binding_kind.is_none() || state.activation_binding_digest == [0; 32] {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    if state.profile_digest != request.prepared.profile_digest {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    if state.pricing_revision_digest != request.pricing_revision_digest {
        return Err(ProviderAdmissionError::PricingRevisionMismatch);
    }
    Ok(())
}

fn verify_prepared(
    transaction: &Transaction<'_>,
    request: &ProviderAuthorityIssueRequest,
) -> Result<(), ProviderAdmissionError> {
    let stored = transaction
        .query_row(
            "SELECT prepared_digest, render_digest, profile_digest, call_digest_version
             FROM provider_prepared_requests WHERE call_id = ?1",
            [request.prepared.call_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    fixed_bytes::<32>(row.get(0)?)?,
                    fixed_bytes::<32>(row.get(1)?)?,
                    fixed_bytes::<32>(row.get(2)?)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
        .ok_or(ProviderAdmissionError::RenderDigestMismatch)?;
    let digest_version = match request.prepared.call_digest_version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    };
    if stored.0 != request.prepared.prepared_digest
        || stored.1 != request.prepared.render_digest
        || stored.2 != request.prepared.profile_digest
        || stored.3 != digest_version
    {
        return Err(ProviderAdmissionError::RenderDigestMismatch);
    }
    Ok(())
}

fn ensure_call_is_unclaimed(
    transaction: &Transaction<'_>,
    call_id: runne_provider::ProviderCallId,
) -> Result<(), ProviderAdmissionError> {
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM provider_dispatch_attempts WHERE call_id = ?1
             )",
            [call_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if exists {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    Ok(())
}

struct ExistingAdmission {
    semantic_digest: [u8; 32],
    state: ProviderRepositoryState,
}

fn load_existing_admission(
    transaction: &Transaction<'_>,
    idempotency_key: &str,
) -> Result<Option<ExistingAdmission>, ProviderAdmissionError> {
    transaction
        .query_row(
            "SELECT admission.semantic_digest, dispatch.state
             FROM provider_execution_admissions admission
             JOIN provider_dispatch_attempts dispatch
               ON dispatch.attempt_id = admission.dispatch_attempt_id
             WHERE admission.provider_idempotency_key = ?1",
            [idempotency_key],
            |row| {
                Ok(ExistingAdmission {
                    semantic_digest: fixed_bytes(row.get(0)?)?,
                    state: decode_repository_state(row.get(1)?)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}
