fn authority_matches_record(authority: &Authority, record: &ProviderEffectAuthorityRecord) -> bool {
    authority.authority_ref == record.authority_ref
        && authority.attempt_id == record.attempt_id
        && authority.permit_id == record.permit_id
        && authority.capability_grant_id == record.capability_grant_id
        && authority.token_reservation_id == record.token_reservation_id
        && authority.cost_reservation_id == record.cost_reservation_id
        && authority.prepared_digest == record.prepared_digest
        && authority.render_digest == record.render_digest
        && authority.profile_digest == record.profile_digest
        && authority.owner_id == record.owner_id
        && authority.scope == record.scope
        && authority.fencing_token == record.fencing_token
        && authority.expires_at == record.expires_at
        && authority.revoked == record.revoked
        && authority.consumed == record.consumed
}

fn validate_authority_record(
    record: &ProviderEffectAuthorityRecord,
) -> Result<(), ProviderAdmissionError> {
    if record.authority_ref.authority_id() == [0; 16]
        || record.authority_ref.revision() == 0
        || record.fencing_token == 0
        || record.capability_grant_id.is_empty()
        || record.capability_grant_id.len() > 256
        || record.owner_id.is_empty()
        || record.owner_id.len() > 256
        || record.scope.is_empty()
        || record.scope.len() > 256
        || record
            .capability_grant_id
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || record.owner_id.bytes().any(|byte| byte.is_ascii_control())
        || record.scope.bytes().any(|byte| byte.is_ascii_control())
        || record.consumed
    {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    Ok(())
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(i64::MAX)
}

fn load_existing(
    transaction: &Transaction<'_>,
    intent_id: &str,
) -> Result<Option<ExistingAdmission>, ProviderAdmissionError> {
    transaction
        .query_row(
            "SELECT auth.grant_id, budget.reservation_id, permit.permit_id
             FROM security_dispatch_intents intent
             JOIN security_authorization_decisions auth USING (intent_id)
             JOIN security_budget_consumptions budget USING (intent_id)
             JOIN security_audit_pre_effect audit USING (intent_id)
             JOIN security_permit_claims permit USING (intent_id)
             WHERE intent.intent_id = ?1 AND intent.status = 'uncertain'
               AND auth.allowed = 1 AND audit.side_effect_started = 1",
            [intent_id],
            |row| {
                Ok(ExistingAdmission {
                    grant_id: row.get(0)?,
                    budget_binding: row.get(1)?,
                    permit_id: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}

fn insert_pre_effect(
    transaction: &Transaction<'_>,
    intent_id: &str,
    authority: &Authority,
) -> Result<(), ProviderAdmissionError> {
    let budget_binding = format!(
        "provider:{}:{}",
        encode_hex(&authority.token_reservation_id),
        encode_hex(&authority.cost_reservation_id)
    );
    let permit_id = encode_hex(&authority.permit_id);
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
                 VALUES (?1, ?2, 1, 'provider-dispatch')",
                params![intent_id, authority.capability_grant_id],
            )
        })
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_budget_consumptions
                 (intent_id, reservation_id, amount) VALUES (?1, ?2, 2)",
                params![intent_id, budget_binding],
            )
        })
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_audit_pre_effect
                 (intent_id, side_effect_started) VALUES (?1, 1)",
                [intent_id],
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
