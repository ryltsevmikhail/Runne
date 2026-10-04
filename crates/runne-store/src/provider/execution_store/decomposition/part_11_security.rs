fn persist_issuance_security_records(
    transaction: &Transaction<'_>,
    intent_id: &str,
    budget_binding: &str,
    permit_id: &str,
    capability_grant_id: &str,
    requested_tokens: i64,
) -> Result<(), ProviderAdmissionError> {
    transaction
        .execute(
            "INSERT INTO security_dispatch_intents (intent_id, status)
             VALUES (?1, 'uncertain')",
            [intent_id],
        )
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_authorization_decisions
                 (intent_id, grant_id, allowed, reason)
                 VALUES (?1, ?2, 1, 'provider-runtime-issued')",
                params![intent_id, capability_grant_id],
            )
        })
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_budget_consumptions
                 (intent_id, reservation_id, amount) VALUES (?1, ?2, ?3)",
                params![intent_id, budget_binding, requested_tokens],
            )
        })
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_permit_claims (permit_id, intent_id)
                 VALUES (?1, ?2)",
                params![permit_id, intent_id],
            )
        })
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    Ok(())
}
