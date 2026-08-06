use gocode_application::provider::{
    ProviderAdmissionError, ProviderAuthorityIssueRequest, ProviderEffectAuthorityRef,
};
use gocode_provider::{DispatchAttemptId, ProviderDispatchClaim};
use rusqlite::{Connection, OptionalExtension, params};

use super::super::authority_state::RuntimeAuthorityState;
use super::{
    DurableProviderAdmission, as_i64, execution_semantic_digest, fixed_bytes, positive_u64,
};

pub(super) fn load_durable_authority_record(
    connection: &Connection,
    request: &ProviderAuthorityIssueRequest,
    state: &RuntimeAuthorityState,
    attempt_id: DispatchAttemptId,
) -> Result<DurableProviderAdmission, ProviderAdmissionError> {
    let durable = connection
        .query_row(
            "SELECT authority_id, authority_revision, generation, permit_id,
                        token_reservation_id, cost_reservation_id, fencing_token
                   FROM provider_execution_admissions
                  WHERE provider_idempotency_key = ?1 AND dispatch_attempt_id = ?2
                    AND semantic_digest = ?3 AND principal_id = ?4
                    AND conversation_id = ?5 AND taskrun_id = ?6
                    AND execution_attempt_id = ?7 AND call_id = ?8
                    AND prepared_digest = ?9 AND render_digest = ?10
                    AND profile_digest = ?11 AND pricing_revision_digest = ?12
                    AND requested_input_tokens = ?13 AND requested_output_tokens = ?14
                    AND max_cost_micros = ?15 AND currency = ?16
                    AND runtime_authority_id = ?17 AND database_generation = ?18
                    AND generation = ?19 AND fencing_token = ?20
                    AND owner_id = ?21 AND scope = ?22
                    AND capability_grant_id = ?23 AND capability_revision = ?24
                    AND capability_expires_at = ?25 AND capability_revocation_epoch = ?26
                    AND capability_revocation_observed = ?27
                    AND approval_id = ?28 AND approval_revision = ?29
                    AND approval_expires_at = ?30 AND approval_revocation_epoch = ?31
                    AND approval_revocation_observed = ?32
                    AND activation_binding_kind = ?33 AND activation_binding_digest = ?34",
            params![
                request.provider_idempotency_key,
                attempt_id.as_bytes().as_slice(),
                execution_semantic_digest(request).as_slice(),
                request.principal_id,
                request.conversation_id.as_bytes().as_slice(),
                request.taskrun_id.as_bytes().as_slice(),
                request.execution_attempt_id.as_bytes().as_slice(),
                request.prepared.call_id.as_bytes().as_slice(),
                request.prepared.prepared_digest.as_slice(),
                request.prepared.render_digest.as_slice(),
                request.prepared.profile_digest.as_slice(),
                request.pricing_revision_digest.as_slice(),
                as_i64(request.requested_input_tokens)?,
                as_i64(request.requested_output_tokens)?,
                as_i64(request.max_cost_micros)?,
                request.currency,
                state.runtime_authority_id.as_slice(),
                as_i64(state.database_generation)?,
                as_i64(state.expected_generation)?,
                as_i64(state.expected_fencing_token)?,
                state.owner_id,
                state.scope,
                state.capability_grant_id,
                as_i64(state.capability_revision)?,
                state.capability_expires_at,
                as_i64(state.capability_revocation_epoch)?,
                i64::from(state.capability_revocation_observed),
                state.approval_id,
                as_i64(state.approval_revision)?,
                state.approval_expires_at,
                as_i64(state.approval_revocation_epoch)?,
                i64::from(state.approval_revocation_observed),
                state
                    .activation_binding_kind
                    .ok_or(ProviderAdmissionError::AuthorityDenied)?
                    .code(),
                state.activation_binding_digest.as_slice(),
            ],
            |row| {
                Ok((
                    fixed_bytes::<16>(row.get(0)?)?,
                    positive_u64(row.get(1)?)?,
                    positive_u64(row.get(2)?)?,
                    fixed_bytes::<16>(row.get(3)?)?,
                    fixed_bytes::<16>(row.get(4)?)?,
                    fixed_bytes::<16>(row.get(5)?)?,
                    positive_u64(row.get(6)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
        .ok_or(ProviderAdmissionError::AuthorityDenied)?;
    let authority_ref = ProviderEffectAuthorityRef::new(durable.0, durable.1)?;
    let claim = ProviderDispatchClaim {
        call_id: request.prepared.call_id,
        attempt_id,
        permit_id: durable.3,
        prepared_digest: request.prepared.prepared_digest,
        render_digest: request.prepared.render_digest,
        profile_digest: request.prepared.profile_digest,
        token_reservation_id: durable.4,
        cost_reservation_id: durable.5,
        fencing_token: durable.6,
        provider_idempotency_key: request.provider_idempotency_key.clone(),
    };
    if claim.permit_id == [0; 16]
        || claim.token_reservation_id == [0; 16]
        || claim.cost_reservation_id == [0; 16]
        || claim.fencing_token == 0
        || durable.2 == 0
    {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    Ok(DurableProviderAdmission {
        authority_ref,
        runtime_generation: durable.2,
        claim,
    })
}
