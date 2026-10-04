fn load_unknown_original_effect(
    connection: &Connection,
    attempt: &ExecutionAttempt,
    expected_provider: &str,
    proof: Option<&OnlineEffectProofCapabilitySet>,
) -> Result<ProviderUnknownCommittedEffectProof, ProviderExecutionError> {
    use crate::provider::execution_store::online_effect_proof::CommittedEffectProofFields;
    let row = connection
        .query_row(
            "SELECT binding.dispatch_attempt_id,binding.provider_id,binding.launch_generation,
                    binding.lifecycle_revision,binding.credential_fence,
                    binding.active_credential_version,binding.active_ref_digest,
                    effect.effect_started_at,effect.effect_expires_at,version.lease_owner,
                    version.lease_expires_at,version.lease_fencing_token,binding.effect_mac,
                    evidence.journal_key_id,evidence.journal_key_version,
                    evidence.journal_runtime_authority_id,evidence.journal_database_generation,
                    evidence.issuance_mac
               FROM provider_effect_starts effect
               JOIN provider_online_credential_effect_bindings binding
                 ON binding.dispatch_attempt_id=effect.dispatch_attempt_id
               JOIN provider_execution_admissions admission
                 ON admission.dispatch_attempt_id=effect.dispatch_attempt_id
               JOIN provider_online_dispatch_issuance_evidence evidence
                 ON evidence.dispatch_attempt_id=effect.dispatch_attempt_id
                AND evidence.provider_id=binding.provider_id
               JOIN provider_credential_versions version
                 ON version.provider_id=binding.provider_id
                AND version.credential_version=binding.active_credential_version
                AND version.ref_digest=binding.active_ref_digest
              WHERE effect.dispatch_attempt_id=?1 AND effect.permit_id=admission.permit_id",
            [attempt.dispatch_attempt_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, Vec<u8>>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, Vec<u8>>(17)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    let binding = ProviderJournalKeyBinding::new(
        unknown_fixed_bytes(row.13)?,
        unknown_positive_u64(row.14)?,
        unknown_fixed_bytes(row.15)?,
        unknown_positive_u64(row.16)?,
    )
    .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if unknown_fixed_bytes::<16>(row.0.clone())? != *attempt.dispatch_attempt_id.as_bytes()
        || row.1 != expected_provider
        || binding.runtime_authority_id() != attempt.runtime_authority_id
        || binding.database_generation() != attempt.database_generation
    {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let fields = CommittedEffectProofFields {
        issuance_mac: unknown_fixed_bytes(row.17)?,
        attempt_id: unknown_fixed_bytes(row.0)?,
        provider_id: row.1,
        launch_generation: unknown_positive_u64(row.2)?,
        lifecycle_revision: unknown_positive_u64(row.3)?,
        credential_fence: unknown_positive_u64(row.4)?,
        credential_version: unknown_positive_u64(row.5)?,
        credential_ref_digest: unknown_fixed_bytes(row.6)?,
        effect_started_at: row.7,
        effect_expires_at: row.8,
        lease_owner: unknown_fixed_bytes(row.9)?,
        lease_expires_at: row.10,
        lease_fence: unknown_positive_u64(row.11)?,
    };
    let mac = unknown_fixed_bytes(row.12)?;
    if proof.is_some_and(|proof| !proof.verify_effect(binding, &fields, &mac)) {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(ProviderUnknownCommittedEffectProof {
        binding,
        fields: ProviderUnknownCommittedEffectFields {
            issuance_mac: fields.issuance_mac,
            attempt_id: fields.attempt_id,
            provider_id: fields.provider_id,
            launch_generation: fields.launch_generation,
            lifecycle_revision: fields.lifecycle_revision,
            credential_fence: fields.credential_fence,
            credential_version: fields.credential_version,
            credential_ref_digest: fields.credential_ref_digest,
            lease_owner: fields.lease_owner,
            lease_expires_at: fields.lease_expires_at,
            lease_fence: fields.lease_fence,
            effect_started_at: fields.effect_started_at,
            effect_expires_at: fields.effect_expires_at,
        },
        mac,
    })
}
