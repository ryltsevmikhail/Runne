use crate::provider::effect_start::verify_historical_issuance;

struct UnknownIssuanceSource {
    provider_id: String,
    principal_id: String,
    conversation_id: [u8; 16],
    taskrun_id: [u8; 16],
    execution_attempt_id: [u8; 16],
    call_id: [u8; 16],
    dispatch_attempt_id: [u8; 16],
    authority_id: [u8; 16],
    authority_revision: u64,
    permit_id: [u8; 16],
    token_reservation_id: [u8; 16],
    cost_reservation_id: [u8; 16],
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    generation: u64,
    fencing_token: u64,
    prepared_digest: [u8; 32],
    render_digest: [u8; 32],
    profile_digest: [u8; 32],
    pricing_revision_digest: [u8; 32],
    semantic_digest: [u8; 32],
    requested_input_tokens: u64,
    requested_output_tokens: u64,
    max_cost_micros: u64,
    currency: String,
    provider_idempotency_key: String,
    call_digest_version: ProviderCallDigestVersion,
    issued_at: i64,
    expires_at: i64,
}

fn verify_unknown_original_issuance(
    connection: &Connection,
    attempt: &ExecutionAttempt,
    proof: &OnlineEffectProofCapabilitySet,
) -> Result<(), ProviderExecutionError> {
    let source = connection
        .query_row(
            "SELECT c.provider_id,a.principal_id,a.conversation_id,a.taskrun_id,
                    a.execution_attempt_id,a.call_id,a.dispatch_attempt_id,a.authority_id,
                    a.authority_revision,a.permit_id,a.token_reservation_id,a.cost_reservation_id,
                    a.runtime_authority_id,a.database_generation,a.generation,a.fencing_token,
                    a.prepared_digest,a.render_digest,a.profile_digest,a.pricing_revision_digest,
                    a.semantic_digest,a.requested_input_tokens,a.requested_output_tokens,
                    a.max_cost_micros,a.currency,a.provider_idempotency_key,p.call_digest_version,
                    a.issued_at,a.expires_at
               FROM provider_execution_admissions a
               JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
                 AND d.call_id=a.call_id AND d.permit_id=a.permit_id
               JOIN provider_prepared_requests p ON p.call_id=a.call_id
               JOIN provider_online_dispatch_claim_providers c
                 ON c.dispatch_attempt_id=d.attempt_id
              WHERE a.dispatch_attempt_id=?1",
            [attempt.dispatch_attempt_id.as_bytes().as_slice()],
            |row| {
                Ok(UnknownIssuanceSource {
                    provider_id: row.get(0)?,
                    principal_id: row.get(1)?,
                    conversation_id: fixed_bytes(row.get(2)?)?,
                    taskrun_id: fixed_bytes(row.get(3)?)?,
                    execution_attempt_id: fixed_bytes(row.get(4)?)?,
                    call_id: fixed_bytes(row.get(5)?)?,
                    dispatch_attempt_id: fixed_bytes(row.get(6)?)?,
                    authority_id: fixed_bytes(row.get(7)?)?,
                    authority_revision: positive_u64(row.get(8)?)?,
                    permit_id: fixed_bytes(row.get(9)?)?,
                    token_reservation_id: fixed_bytes(row.get(10)?)?,
                    cost_reservation_id: fixed_bytes(row.get(11)?)?,
                    runtime_authority_id: fixed_bytes(row.get(12)?)?,
                    database_generation: positive_u64(row.get(13)?)?,
                    generation: positive_u64(row.get(14)?)?,
                    fencing_token: positive_u64(row.get(15)?)?,
                    prepared_digest: fixed_bytes(row.get(16)?)?,
                    render_digest: fixed_bytes(row.get(17)?)?,
                    profile_digest: fixed_bytes(row.get(18)?)?,
                    pricing_revision_digest: fixed_bytes(row.get(19)?)?,
                    semantic_digest: fixed_bytes(row.get(20)?)?,
                    requested_input_tokens: nonnegative_u64(row.get(21)?)?,
                    requested_output_tokens: positive_u64(row.get(22)?)?,
                    max_cost_micros: nonnegative_u64(row.get(23)?)?,
                    currency: row.get(24)?,
                    provider_idempotency_key: row.get(25)?,
                    call_digest_version: decode_call_digest_version(row.get(26)?)?,
                    issued_at: row.get(27)?,
                    expires_at: row.get(28)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    let issuance = verify_historical_issuance(
        connection,
        source.dispatch_attempt_id,
        &source.provider_id,
        proof,
    )
    .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let semantic_digest = execution_semantic_digest_source(&ExecutionSemanticSource {
        principal_id: &source.principal_id,
        conversation_id: &source.conversation_id,
        taskrun_id: &source.taskrun_id,
        execution_attempt_id: &source.execution_attempt_id,
        call_id: &source.call_id,
        call_digest_version: source.call_digest_version,
        prepared_digest: source.prepared_digest,
        render_digest: source.render_digest,
        profile_digest: source.profile_digest,
        pricing_revision_digest: source.pricing_revision_digest,
        requested_input_tokens: source.requested_input_tokens,
        requested_output_tokens: source.requested_output_tokens,
        max_cost_micros: source.max_cost_micros,
        currency: &source.currency,
        provider_idempotency_key: &source.provider_idempotency_key,
    });
    let fields = issuance.fields;
    if semantic_digest != source.semantic_digest
        || fields.provider_id != source.provider_id
        || fields.provider_idempotency_key != source.provider_idempotency_key
        || fields.call_id != source.call_id
        || fields.attempt_id != source.dispatch_attempt_id
        || fields.authority_id != source.authority_id
        || fields.authority_revision != source.authority_revision
        || fields.semantic_digest != source.semantic_digest
        || fields.permit_id != source.permit_id
        || fields.token_reservation_id != source.token_reservation_id
        || fields.cost_reservation_id != source.cost_reservation_id
        || fields.runtime_authority_id != source.runtime_authority_id
        || fields.database_generation != source.database_generation
        || fields.key.runtime_authority_id() != source.runtime_authority_id
        || fields.key.database_generation() != source.database_generation
        || fields.generation != source.generation
        || fields.fencing_token != source.fencing_token
        || fields.prepared_digest != source.prepared_digest
        || fields.render_digest != source.render_digest
        || fields.profile_digest != source.profile_digest
        || fields.pricing_revision_digest != source.pricing_revision_digest
        || fields.issued_at != source.issued_at
        || fields.expires_at != source.expires_at
        || source.dispatch_attempt_id != *attempt.dispatch_attempt_id.as_bytes()
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(())
}
