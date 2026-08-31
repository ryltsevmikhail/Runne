fn persist_online_issuance_binding(
    transaction: &Transaction<'_>,
    request: &ProviderAuthorityIssueRequest,
    claim: &ProviderDispatchClaim,
    proof: &OnlineEffectProofCapabilitySet,
) -> Result<(), ProviderAdmissionError> {
    let key = proof.binding();
    let fields = transaction
        .query_row(
            "SELECT provider_idempotency_key, semantic_digest, call_id, dispatch_attempt_id,
                    authority_id, authority_revision, permit_id, token_reservation_id,
                    cost_reservation_id, runtime_authority_id, database_generation, generation,
                    fencing_token, prepared_digest, render_digest, profile_digest,
                    pricing_revision_digest, issued_at, expires_at
               FROM provider_execution_admissions WHERE dispatch_attempt_id=?1",
            [claim.attempt_id.as_bytes().as_slice()],
            |row| {
                Ok(online_effect_proof::IssuanceProofFields {
                    proof_version: 1,
                    key,
                    runtime_authority_id: issuance_array(row, 9)?,
                    database_generation: issuance_u64(row, 10)?,
                    provider_id: request.provider_id.as_str().to_owned(),
                    provider_idempotency_key: row.get(0)?,
                    semantic_digest: issuance_array(row, 1)?,
                    call_id: issuance_array(row, 2)?,
                    attempt_id: issuance_array(row, 3)?,
                    authority_id: issuance_array(row, 4)?,
                    authority_revision: issuance_u64(row, 5)?,
                    permit_id: issuance_array(row, 6)?,
                    token_reservation_id: issuance_array(row, 7)?,
                    cost_reservation_id: issuance_array(row, 8)?,
                    generation: issuance_u64(row, 11)?,
                    fencing_token: issuance_u64(row, 12)?,
                    prepared_digest: issuance_array(row, 13)?,
                    render_digest: issuance_array(row, 14)?,
                    profile_digest: issuance_array(row, 15)?,
                    pricing_revision_digest: issuance_array(row, 16)?,
                    issued_at: row.get(17)?,
                    expires_at: row.get(18)?,
                })
            },
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    let mac = proof.issue(&fields)?;
    transaction
        .execute(
            "INSERT INTO provider_online_dispatch_issuance_evidence (
                dispatch_attempt_id, provider_id, authority_id, authority_revision, issued_at,
                proof_version, journal_key_id, journal_key_version, journal_runtime_authority_id,
                journal_database_generation, issuance_mac
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                fields.attempt_id.as_slice(),
                fields.provider_id,
                fields.authority_id.as_slice(),
                i64::try_from(fields.authority_revision)
                    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                fields.issued_at,
                i64::try_from(fields.proof_version)
                    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                key.key_id().as_slice(),
                i64::try_from(key.key_version())
                    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                key.runtime_authority_id().as_slice(),
                i64::try_from(key.database_generation())
                    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                mac.as_slice(),
            ],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    transaction
        .execute(
            "INSERT INTO provider_online_dispatch_claim_providers (dispatch_attempt_id, provider_id)
             VALUES (?1, ?2)",
            params![fields.attempt_id.as_slice(), fields.provider_id],
        )
        .map(|_| ())
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}

fn issuance_array<const N: usize>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<[u8; N]> {
    row.get::<_, Vec<u8>>(index)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn issuance_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(row.get::<_, i64>(index)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
