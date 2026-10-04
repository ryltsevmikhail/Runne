use super::*;
use rusqlite::{OptionalExtension, Transaction, params};

pub(super) fn verify_effect_authority(
    transaction: &Transaction<'_>,
    claim: &ProviderDispatchClaim,
    credential: &CredentialDispatchBinding,
    observed: i64,
) -> Result<bool, ProviderAdmissionError> {
    let secondary_identity: Option<(String, String)> = transaction
        .query_row(
            "SELECT grant_row.provider_id, grant_row.credential_realm
             FROM provider_secondary_profile_attempts binding
             JOIN provider_secondary_profile_grants grant_row USING(grant_id)
             WHERE binding.dispatch_attempt_id=?1",
            [claim.attempt_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if secondary_identity.is_some_and(|(provider, realm)| {
        provider != claim.provider_id.as_str()
            || provider != realm
            || realm != credential.version_ref().provider().as_str()
    }) {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    let valid = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM provider_execution_admissions admission
            JOIN provider_dispatch_attempts dispatch
              ON dispatch.attempt_id = admission.dispatch_attempt_id
            JOIN provider_runtime_authority_state runtime ON runtime.id = 1
            JOIN provider_effect_authorities authority
              ON authority.authority_id = admission.authority_id
             AND authority.revision = admission.authority_revision
            WHERE admission.dispatch_attempt_id = ?1 AND admission.permit_id = ?2
              AND admission.provider_idempotency_key = ?3
              AND admission.prepared_digest = ?4 AND admission.render_digest = ?5
              AND admission.profile_digest = ?6 AND admission.fencing_token = ?7
              AND admission.token_reservation_id = ?9 AND admission.cost_reservation_id = ?10
              AND dispatch.state = 1 AND dispatch.permit_id = ?2
              AND dispatch.prepared_digest = ?4 AND dispatch.render_digest = ?5
              AND dispatch.profile_digest = ?6 AND dispatch.fencing_token = ?7
              AND dispatch.token_reservation_id = ?9 AND dispatch.cost_reservation_id = ?10
              AND runtime.active = 1
              AND runtime.expected_generation = runtime.lease_generation
              AND runtime.expected_fencing_token = runtime.lease_fencing_token
              AND runtime.runtime_authority_id = admission.runtime_authority_id
              AND runtime.database_generation = admission.database_generation
              AND runtime.expected_generation = admission.generation
              AND runtime.expected_fencing_token = admission.fencing_token
              AND runtime.principal_id = admission.principal_id
              AND runtime.owner_id = admission.owner_id AND runtime.scope = admission.scope
              AND runtime.capability_grant_id = admission.capability_grant_id
              AND runtime.capability_revision = admission.capability_revision
              AND runtime.capability_expires_at = admission.capability_expires_at
              AND runtime.capability_revocation_epoch = admission.capability_revocation_epoch
              AND runtime.capability_revocation_observed = admission.capability_revocation_observed
              AND runtime.approval_id = admission.approval_id
              AND runtime.approval_revision = admission.approval_revision
              AND runtime.approval_expires_at = admission.approval_expires_at
              AND runtime.approval_revocation_epoch = admission.approval_revocation_epoch
              AND runtime.approval_revocation_observed = admission.approval_revocation_observed
              AND (
                (NOT EXISTS(SELECT 1 FROM provider_secondary_profile_attempts binding
                    WHERE binding.dispatch_attempt_id=admission.dispatch_attempt_id)
                 AND runtime.profile_digest=admission.profile_digest
                 AND runtime.pricing_revision_digest=admission.pricing_revision_digest)
                OR EXISTS(SELECT 1 FROM provider_secondary_profile_attempts binding
                    JOIN provider_secondary_profile_grants grant_row USING(grant_id)
                    JOIN provider_secondary_profile_bindings grant_binding ON grant_binding.binding_id=binding.binding_id
                    WHERE binding.dispatch_attempt_id=admission.dispatch_attempt_id
                      AND grant_binding.grant_id=binding.grant_id
                      AND binding.provider_idempotency_key=admission.provider_idempotency_key
                      AND binding.profile_digest=admission.profile_digest
                      AND binding.pricing_revision_digest=admission.pricing_revision_digest
                      AND grant_row.enabled=1 AND grant_binding.closed_at IS NULL
                      AND grant_row.runtime_authority_id=runtime.runtime_authority_id
                      AND grant_row.database_generation=runtime.database_generation
                      AND grant_binding.owner_id=runtime.owner_id
                      AND grant_binding.authority_revision=runtime.state_revision
                      AND grant_binding.scope=runtime.scope
                      AND grant_binding.activation_binding_kind=runtime.activation_binding_kind
                      AND grant_binding.activation_binding_digest=runtime.activation_binding_digest
                      AND grant_row.profile_digest=admission.profile_digest
                      AND grant_row.pricing_revision_digest=admission.pricing_revision_digest
                      AND grant_row.provider_id=grant_row.credential_realm
                      AND grant_row.provider_id=?17)
              )
              AND runtime.activation_binding_kind = admission.activation_binding_kind
              AND runtime.activation_binding_digest = admission.activation_binding_digest
              AND runtime.capability_allowed = 1 AND runtime.approval_allowed = 1
              AND runtime.capability_expires_at > ?8 AND runtime.approval_expires_at > ?8
              AND authority.attempt_id = admission.dispatch_attempt_id
              AND authority.permit_id = admission.permit_id
              AND authority.token_reservation_id = admission.token_reservation_id
              AND authority.cost_reservation_id = admission.cost_reservation_id
              AND authority.prepared_digest = admission.prepared_digest
              AND authority.render_digest = admission.render_digest
              AND authority.profile_digest = admission.profile_digest
              AND authority.owner_id = admission.owner_id AND authority.scope = admission.scope
              AND authority.fencing_token = admission.fencing_token
              AND authority.expires_at > ?8 AND authority.revoked = 0 AND authority.consumed = 1
              AND authority.consumed_intent_id = ('provider:' || lower(hex(admission.dispatch_attempt_id)))
              AND EXISTS(SELECT 1 FROM provider_budget_reservations b
                         WHERE b.provider_idempotency_key = admission.provider_idempotency_key
                           AND b.dimension = 1 AND b.reservation_id = admission.token_reservation_id
                           AND b.state = 1)
              AND EXISTS(SELECT 1 FROM provider_budget_reservations b
                         WHERE b.provider_idempotency_key = admission.provider_idempotency_key
                           AND b.dimension = 2 AND b.reservation_id = admission.cost_reservation_id
                           AND b.state = 1)
              AND EXISTS(SELECT 1 FROM provider_credential_versions credential
                         WHERE credential.provider_id = ?11
                           AND credential.credential_version = ?12
                           AND credential.ref_digest = ?13
                           AND credential.lifecycle_state = 'ACTIVE'
                           AND credential.lease_owner = ?14
                           AND credential.lease_expires_at = ?15
                           AND credential.lease_fencing_token = ?16
                           AND credential.lease_expires_at > ?8
                           AND credential.revocation_fence < credential.lease_fencing_token
                           AND NOT EXISTS(
                               SELECT 1 FROM provider_credential_authority_heads online_head
                               WHERE online_head.provider_id = credential.provider_id))
        )",
        params![
            claim.attempt_id.as_bytes().as_slice(), claim.permit_id.as_slice(),
            claim.provider_idempotency_key, claim.prepared_digest.as_slice(),
            claim.render_digest.as_slice(), claim.profile_digest.as_slice(),
            i64::try_from(claim.fencing_token).map_err(|_| ProviderAdmissionError::StaleFencingToken)?, observed,
            claim.token_reservation_id.as_slice(), claim.cost_reservation_id.as_slice(),
            credential.version_ref().provider().as_str(),
            i64::try_from(credential.version_ref().version()).map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            credential.version_ref().ref_digest().as_slice(), credential.owner().as_slice(),
            credential.expires_at(),
            i64::try_from(credential.fencing_token()).map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            claim.provider_id.as_str(),
        ], |row| row.get::<_, bool>(0),
    ).map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    Ok(valid)
}
