fn validate_remote_identity(
    binding: &ProviderRemoteAttemptBinding,
    key: ProviderJournalKeyBinding,
    encrypted: &ProviderEncryptedPayload,
    maximum: usize,
) -> Result<(), ProviderExecutionError> {
    if binding.provider_id.is_empty()
        || binding.provider_id.len() > 128
        || binding.profile_id.is_empty()
        || binding.profile_id.len() > 128
        || binding.credential_realm.is_empty()
        || binding.credential_realm.len() > 128
        || binding.profile_digest == [0; 32]
        || binding.pricing_digest == [0; 32]
        || binding.semantic_digest == [0; 32]
        || binding.prepared_digest == [0; 32]
        || binding.request_digest == [0; 32]
        || binding.runtime_authority_id == [0; 16]
        || binding.database_generation == 0
        || binding.runtime_generation == 0
        || binding.fencing_token == 0
        || key.runtime_authority_id() != binding.runtime_authority_id
        || key.database_generation() != binding.database_generation
        || encrypted.plaintext_len() == 0
        || encrypted.plaintext_len() as usize > maximum
        || encrypted.ciphertext().len() != encrypted.plaintext_len() as usize + 16
    {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(())
}

fn validate_current_remote_binding(
    tx: &Transaction<'_>,
    b: &ProviderRemoteAttemptBinding,
    key: ProviderJournalKeyBinding,
    now: i64,
) -> Result<(), ProviderExecutionError> {
    let matches: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions a
         JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
         JOIN provider_effect_starts e USING(dispatch_attempt_id)
         JOIN provider_online_dispatch_claim_providers p USING(dispatch_attempt_id)
         JOIN provider_online_credential_effect_bindings c USING(dispatch_attempt_id)
         JOIN provider_journal_key_refs k ON k.key_id=?12 AND k.key_version=?13
         JOIN provider_runtime_authority_state s ON s.id=1
         WHERE a.dispatch_attempt_id=?1 AND a.taskrun_id=?2 AND a.execution_attempt_id=?3
           AND a.provider_idempotency_key IS NOT NULL AND a.profile_digest=?4
           AND a.pricing_revision_digest=?5 AND a.semantic_digest=?6
           AND a.prepared_digest=?7 AND a.render_digest=?8
           AND a.runtime_authority_id=?9 AND a.database_generation=?10
           AND a.generation=?11 AND a.fencing_token=?14 AND d.state=1
           AND e.permit_id=a.permit_id AND e.provider_idempotency_key=a.provider_idempotency_key
           AND e.state=1 AND e.effect_started_at<=?17 AND e.effect_expires_at>?17
           AND p.provider_id=?15 AND c.provider_id=?16
           AND k.runtime_authority_id=?9 AND k.database_generation=?10
           AND s.active=1 AND s.runtime_authority_id=?9 AND s.database_generation=?10
           AND s.expected_generation=?11 AND s.expected_fencing_token=?14)",
            rusqlite::params![
                b.dispatch_attempt_id.as_bytes().as_slice(),
                b.taskrun_id.as_bytes().as_slice(),
                b.taskrun_attempt_id.as_bytes().as_slice(),
                b.profile_digest.as_slice(),
                b.pricing_digest.as_slice(),
                b.semantic_digest.as_slice(),
                b.prepared_digest.as_slice(),
                b.request_digest.as_slice(),
                b.runtime_authority_id.as_slice(),
                i64::try_from(b.database_generation).unwrap_or(-1),
                i64::try_from(b.runtime_generation).unwrap_or(-1),
                key.key_id().as_slice(),
                i64::try_from(key.key_version()).unwrap_or(-1),
                i64::try_from(b.fencing_token).unwrap_or(-1),
                b.provider_id,
                b.credential_realm,
                now
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if !matches {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    super::dispatch_store::verify_online_publication(tx, b.dispatch_attempt_id, Some(now))
        .map_err(|_| ProviderExecutionError::StaleGeneration)?;
    let secondary = secondary_profile_grant::verify_secondary_attempt_binding(
        tx,
        b.dispatch_attempt_id,
        b.profile_digest,
        b.pricing_digest,
        true,
    )?;
    if !secondary && (b.provider_id != b.credential_realm || b.provider_id == "openai-background") {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    Ok(())
}

/// Validates a response ID against the immutable effect that already crossed
/// the send boundary; this does not authorize a new send or publication.
fn validate_historical_response_binding(
    tx: &Transaction<'_>,
    b: &ProviderRemoteAttemptBinding,
    key: ProviderJournalKeyBinding,
    now: i64,
) -> Result<(), ProviderExecutionError> {
    let matches: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_remote_request_intents r
         JOIN provider_execution_admissions a USING(dispatch_attempt_id)
         JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
         JOIN provider_effect_starts e USING(dispatch_attempt_id)
         JOIN provider_online_dispatch_claim_providers p USING(dispatch_attempt_id)
         JOIN provider_online_credential_effect_bindings c USING(dispatch_attempt_id)
         JOIN provider_journal_key_refs k ON k.key_id=?12 AND k.key_version=?13
         WHERE r.dispatch_attempt_id=?1 AND r.taskrun_id=?2
           AND r.taskrun_attempt_id=?3 AND r.provider_id=?15 AND r.profile_id=?18
           AND r.credential_realm=?16
           AND r.profile_digest=?4 AND r.pricing_revision_digest=?5 AND r.semantic_digest=?6
           AND r.prepared_digest=?7 AND r.request_digest=?8
           AND r.runtime_authority_id=?9 AND r.database_generation=?10
           AND r.runtime_generation=?11 AND r.fencing_token=?14
           AND r.key_id=?12 AND r.key_version=?13
           AND a.taskrun_id=?2 AND a.execution_attempt_id=?3
           AND a.profile_digest=?4 AND a.pricing_revision_digest=?5
           AND a.semantic_digest=?6 AND a.prepared_digest=?7 AND a.render_digest=?8
           AND a.runtime_authority_id=?9 AND a.database_generation=?10
           AND a.generation=?11 AND a.fencing_token=?14
           AND e.permit_id=a.permit_id AND e.provider_idempotency_key=a.provider_idempotency_key
           AND e.effect_started_at<=?17 AND p.provider_id=?15 AND c.provider_id=?16
           AND k.runtime_authority_id=?9 AND k.database_generation=?10)",
            rusqlite::params![
                b.dispatch_attempt_id.as_bytes().as_slice(),
                b.taskrun_id.as_bytes().as_slice(),
                b.taskrun_attempt_id.as_bytes().as_slice(),
                b.profile_digest.as_slice(),
                b.pricing_digest.as_slice(),
                b.semantic_digest.as_slice(),
                b.prepared_digest.as_slice(),
                b.request_digest.as_slice(),
                b.runtime_authority_id.as_slice(),
                i64::try_from(b.database_generation).unwrap_or(-1),
                i64::try_from(b.runtime_generation).unwrap_or(-1),
                key.key_id().as_slice(),
                i64::try_from(key.key_version()).unwrap_or(-1),
                i64::try_from(b.fencing_token).unwrap_or(-1),
                b.provider_id,
                b.credential_realm,
                now,
                b.profile_id,
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if !matches {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    let secondary = secondary_profile_grant::verify_secondary_attempt_binding(
        tx,
        b.dispatch_attempt_id,
        b.profile_digest,
        b.pricing_digest,
        false,
    );
    let secondary = secondary?;
    if !secondary && (b.provider_id != b.credential_realm || b.provider_id == "openai-background") {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    Ok(())
}
