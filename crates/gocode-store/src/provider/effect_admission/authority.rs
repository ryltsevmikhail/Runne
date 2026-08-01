fn load_authority(
    transaction: &Transaction<'_>,
    authority_ref: ProviderEffectAuthorityRef,
) -> Result<Option<Authority>, ProviderAdmissionError> {
    transaction
        .query_row(
            "SELECT attempt_id, permit_id, capability_grant_id, token_reservation_id,
                    cost_reservation_id, prepared_digest, render_digest, profile_digest,
                    owner_id, scope, fencing_token, expires_at, revoked, consumed
             FROM provider_effect_authorities WHERE authority_id = ?1 AND revision = ?2",
            params![
                authority_ref.authority_id().as_slice(),
                i64::try_from(authority_ref.revision())
                    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            ],
            |row| {
                let fence: i64 = row.get(10)?;
                Ok(Authority {
                    authority_ref,
                    attempt_id: gocode_provider::DispatchAttemptId::from_bytes(fixed_bytes(
                        row.get(0)?,
                    )?),
                    permit_id: fixed_bytes(row.get(1)?)?,
                    capability_grant_id: row.get(2)?,
                    token_reservation_id: fixed_bytes(row.get(3)?)?,
                    cost_reservation_id: fixed_bytes(row.get(4)?)?,
                    prepared_digest: fixed_bytes(row.get(5)?)?,
                    render_digest: fixed_bytes(row.get(6)?)?,
                    profile_digest: fixed_bytes(row.get(7)?)?,
                    owner_id: row.get(8)?,
                    scope: row.get(9)?,
                    fencing_token: u64::try_from(fence)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    expires_at: row.get(11)?,
                    revoked: row.get::<_, i64>(12)? == 1,
                    consumed: row.get::<_, i64>(13)? == 1,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}

fn verify_authority(
    authority: &Authority,
    request: &ProviderEffectRequest,
) -> Result<(), ProviderAdmissionError> {
    if authority.attempt_id != request.attempt_id
        || authority.permit_id != request.permit_id
        || authority.token_reservation_id != request.token_reservation_id
        || authority.cost_reservation_id != request.cost_reservation_id
        || authority.prepared_digest != request.prepared_digest
        || authority.render_digest != request.render_digest
        || authority.profile_digest != request.profile_digest
        || authority.fencing_token != request.fencing_token
        || authority.owner_id != request.owner_id
        || authority.scope != request.scope
    {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    Ok(())
}

fn consume_authority(
    transaction: &Transaction<'_>,
    authority: &Authority,
    intent_id: &str,
) -> Result<(), ProviderAdmissionError> {
    let changed = transaction
        .execute(
            "UPDATE provider_effect_authorities SET consumed = 1, consumed_intent_id = ?3
         WHERE authority_id = ?1 AND revision = ?2 AND consumed = 0 AND revoked = 0",
            params![
                authority.authority_ref.authority_id().as_slice(),
                i64::try_from(authority.authority_ref.revision())
                    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                intent_id,
            ],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if changed != 1 {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    Ok(())
}
