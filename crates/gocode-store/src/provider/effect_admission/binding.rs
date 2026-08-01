fn load_dispatch_binding(
    transaction: &Transaction<'_>,
    request: &ProviderEffectRequest,
) -> Result<DispatchBinding, ProviderAdmissionError> {
    transaction
        .query_row(
            "SELECT permit_id, token_reservation_id, cost_reservation_id,
                    fencing_token, prepared_digest, render_digest, profile_digest, state
             FROM provider_dispatch_attempts WHERE attempt_id = ?1",
            [request.attempt_id.as_bytes().as_slice()],
            |row| {
                let fencing_token: i64 = row.get(3)?;
                Ok(DispatchBinding {
                    permit_id: fixed_bytes(row.get(0)?)?,
                    token_reservation_id: fixed_bytes(row.get(1)?)?,
                    cost_reservation_id: fixed_bytes(row.get(2)?)?,
                    fencing_token: u64::try_from(fencing_token)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    prepared_digest: fixed_bytes(row.get(4)?)?,
                    render_digest: fixed_bytes(row.get(5)?)?,
                    profile_digest: fixed_bytes(row.get(6)?)?,
                    state: row.get(7)?,
                })
            },
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}

fn verify_dispatch_binding(
    stored: &DispatchBinding,
    request: &ProviderEffectRequest,
) -> Result<(), ProviderAdmissionError> {
    if stored.permit_id != request.permit_id {
        return Err(ProviderAdmissionError::PermitMismatch);
    }
    if stored.token_reservation_id != request.token_reservation_id {
        return Err(ProviderAdmissionError::TokenReservationMismatch);
    }
    if stored.cost_reservation_id != request.cost_reservation_id {
        return Err(ProviderAdmissionError::CostReservationMismatch);
    }
    if stored.fencing_token != request.fencing_token {
        return Err(ProviderAdmissionError::StaleFencingToken);
    }
    if stored.prepared_digest != request.prepared_digest
        || stored.render_digest != request.render_digest
    {
        return Err(ProviderAdmissionError::RenderDigestMismatch);
    }
    if stored.profile_digest != request.profile_digest {
        return Err(ProviderAdmissionError::RenderDigestMismatch);
    }
    Ok(())
}

struct ExistingAdmission {
    grant_id: String,
    budget_binding: String,
    permit_id: String,
}

fn existing_matches_authority(existing: &ExistingAdmission, authority: &Authority) -> bool {
    existing.grant_id == authority.capability_grant_id
        && existing.budget_binding
            == format!(
                "provider:{}:{}",
                encode_hex(&authority.token_reservation_id),
                encode_hex(&authority.cost_reservation_id)
            )
        && existing.permit_id == encode_hex(&authority.permit_id)
}
