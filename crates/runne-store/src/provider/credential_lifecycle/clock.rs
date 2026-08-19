pub(super) fn advance_provider_clock(
    transaction: &rusqlite::Transaction<'_>,
    provider: &runne_provider::ProviderId,
    observed_at: i64,
) -> Result<(), CredentialLifecycleError> {
    let proposal = propose_provider_clock(transaction, provider, observed_at)?;
    apply_provider_clock(transaction, &proposal)
}

pub(super) struct ProviderClockAdvance {
    provider: runne_provider::ProviderId,
    observed_at: i64,
}

pub(super) fn propose_provider_clock(
    transaction: &rusqlite::Transaction<'_>,
    provider: &runne_provider::ProviderId,
    observed_at: i64,
) -> Result<ProviderClockAdvance, CredentialLifecycleError> {
    if observed_at < 0 {
        return Err(CredentialLifecycleError::InvalidInput);
    }
    let high_water: Option<i64> = transaction
        .query_row(
            "SELECT observed_at FROM provider_credential_clock_high_water
             WHERE provider_id=?1",
            [provider.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sql)?;
    if high_water.is_some_and(|high_water| observed_at < high_water) {
        return Err(CredentialLifecycleError::StaleLease);
    }
    Ok(ProviderClockAdvance {
        provider: provider.clone(),
        observed_at,
    })
}

pub(super) fn apply_provider_clock(
    transaction: &rusqlite::Transaction<'_>,
    proposal: &ProviderClockAdvance,
) -> Result<(), CredentialLifecycleError> {
    transaction
        .execute(
            "INSERT INTO provider_credential_clock_high_water(provider_id, observed_at)
             VALUES (?1, ?2)
             ON CONFLICT(provider_id) DO UPDATE SET observed_at=excluded.observed_at",
            params![proposal.provider.as_str(), proposal.observed_at],
        )
        .map_err(map_sql)?;
    Ok(())
}
