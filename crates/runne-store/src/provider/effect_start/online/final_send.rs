use crate::provider::execution_store::online_effect_proof::OnlineEffectProofCapabilitySet;
use runne_application::provider::ProviderAdmissionError;
use runne_provider::ProviderDispatchClaim;
use rusqlite::{Transaction, params};

pub(in crate::provider::effect_start) fn verify_final_send(
    transaction: &Transaction<'_>,
    claim: &ProviderDispatchClaim,
    proof: &OnlineEffectProofCapabilitySet,
    observed: i64,
) -> Result<(), ProviderAdmissionError> {
    let valid: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions admission
         JOIN provider_effect_starts effect ON effect.dispatch_attempt_id=admission.dispatch_attempt_id
         JOIN provider_dispatch_attempts dispatch ON dispatch.attempt_id=admission.dispatch_attempt_id
         JOIN provider_runtime_authority_state runtime ON runtime.id=1
         JOIN provider_effect_authorities authority ON authority.authority_id=admission.authority_id
           AND authority.revision=admission.authority_revision
         JOIN provider_online_credential_effect_bindings binding
           ON binding.dispatch_attempt_id=admission.dispatch_attempt_id
         JOIN provider_credential_authority_heads head ON head.provider_id=binding.provider_id
         JOIN provider_credential_versions version ON version.provider_id=head.provider_id
           AND version.credential_version=binding.active_credential_version
           AND version.ref_digest=binding.active_ref_digest
         WHERE admission.dispatch_attempt_id=?1 AND admission.provider_idempotency_key=?2
           AND admission.permit_id=?3 AND admission.prepared_digest=?4
           AND admission.render_digest=?5 AND admission.profile_digest=?6
           AND admission.fencing_token=?7 AND admission.token_reservation_id=?8
           AND admission.cost_reservation_id=?9
           AND effect.provider_idempotency_key=admission.provider_idempotency_key
           AND effect.permit_id=admission.permit_id AND effect.state=1 AND effect.effect_expires_at>?11
           AND dispatch.state=1 AND dispatch.permit_id=admission.permit_id
           AND dispatch.prepared_digest=admission.prepared_digest
           AND dispatch.render_digest=admission.render_digest AND dispatch.profile_digest=admission.profile_digest
           AND dispatch.fencing_token=admission.fencing_token
           AND dispatch.token_reservation_id=admission.token_reservation_id
           AND dispatch.cost_reservation_id=admission.cost_reservation_id
           AND runtime.active=1 AND runtime.expected_generation=runtime.lease_generation
           AND runtime.expected_fencing_token=runtime.lease_fencing_token
           AND runtime.runtime_authority_id=admission.runtime_authority_id
           AND runtime.database_generation=admission.database_generation
           AND runtime.expected_generation=admission.generation
           AND runtime.expected_fencing_token=admission.fencing_token
           AND runtime.state_revision=admission.authority_revision
           AND runtime.principal_id=admission.principal_id AND runtime.owner_id=admission.owner_id
           AND runtime.scope=admission.scope AND runtime.capability_allowed=1 AND runtime.approval_allowed=1
           AND runtime.capability_grant_id=admission.capability_grant_id
           AND runtime.capability_revision=admission.capability_revision
           AND runtime.capability_expires_at=admission.capability_expires_at
           AND runtime.capability_revocation_epoch=admission.capability_revocation_epoch
           AND runtime.capability_revocation_observed=admission.capability_revocation_observed
           AND runtime.approval_id=admission.approval_id
           AND runtime.approval_revision=admission.approval_revision
           AND runtime.approval_expires_at=admission.approval_expires_at
           AND runtime.approval_revocation_epoch=admission.approval_revocation_epoch
           AND runtime.approval_revocation_observed=admission.approval_revocation_observed
           AND runtime.capability_expires_at>?11 AND runtime.approval_expires_at>?11
           AND runtime.activation_binding_kind=admission.activation_binding_kind
           AND runtime.activation_binding_digest=admission.activation_binding_digest
           AND authority.attempt_id=admission.dispatch_attempt_id AND authority.permit_id=admission.permit_id
           AND authority.token_reservation_id=admission.token_reservation_id
           AND authority.cost_reservation_id=admission.cost_reservation_id
           AND authority.prepared_digest=admission.prepared_digest
           AND authority.render_digest=admission.render_digest AND authority.profile_digest=admission.profile_digest
           AND authority.fencing_token=admission.fencing_token
           AND authority.owner_id=admission.owner_id AND authority.scope=admission.scope
           AND authority.expires_at>?11 AND authority.revoked=0 AND authority.consumed=1
           AND authority.consumed_intent_id=('provider:' || lower(hex(admission.dispatch_attempt_id)))
           AND EXISTS(SELECT 1 FROM provider_budget_reservations b WHERE b.provider_idempotency_key=admission.provider_idempotency_key AND b.dimension=1 AND b.reservation_id=admission.token_reservation_id AND b.state=1)
           AND EXISTS(SELECT 1 FROM provider_budget_reservations b WHERE b.provider_idempotency_key=admission.provider_idempotency_key AND b.dimension=2 AND b.reservation_id=admission.cost_reservation_id AND b.state=1)
           AND EXISTS(SELECT 1 FROM provider_online_dispatch_claim_providers p
             JOIN provider_online_dispatch_issuance_evidence issued
               ON issued.dispatch_attempt_id=p.dispatch_attempt_id
              AND issued.provider_id=p.provider_id
              AND issued.authority_id=admission.authority_id
              AND issued.authority_revision=admission.authority_revision
              AND issued.journal_runtime_authority_id=admission.runtime_authority_id
              AND issued.journal_database_generation=admission.database_generation
             WHERE p.dispatch_attempt_id=admission.dispatch_attempt_id AND p.provider_id=?10)
           AND binding.provider_id=?10 AND binding.launch_generation=runtime.expected_generation
           AND binding.lifecycle_revision=head.lifecycle_revision AND binding.credential_fence=head.credential_fence
           AND binding.active_credential_version=head.active_credential_version
           AND binding.active_ref_digest=head.active_ref_digest
           AND head.hard_fence_disposition IS NULL AND head.release_migration_state IN ('NONE','CLEARED')
           AND version.lifecycle_state='ACTIVE' AND version.revocation_fence < version.lease_fencing_token
           AND version.lease_expires_at>?11
           AND ((NOT EXISTS(SELECT 1 FROM provider_secondary_profile_attempts s WHERE s.dispatch_attempt_id=admission.dispatch_attempt_id)
                 AND runtime.profile_digest=admission.profile_digest
                 AND runtime.pricing_revision_digest=admission.pricing_revision_digest)
             OR EXISTS(SELECT 1 FROM provider_secondary_profile_attempts s
               JOIN provider_secondary_profile_grants g USING(grant_id)
               JOIN provider_secondary_profile_bindings gb ON gb.binding_id=s.binding_id
               WHERE s.dispatch_attempt_id=admission.dispatch_attempt_id AND gb.grant_id=s.grant_id
                 AND s.provider_idempotency_key=admission.provider_idempotency_key
                 AND s.profile_digest=admission.profile_digest
                 AND s.pricing_revision_digest=admission.pricing_revision_digest
                 AND g.enabled=1 AND gb.closed_at IS NULL
                 AND g.runtime_authority_id=runtime.runtime_authority_id
                 AND g.database_generation=runtime.database_generation AND gb.owner_id=runtime.owner_id
                 AND gb.authority_revision=runtime.state_revision AND gb.scope=runtime.scope
                 AND gb.activation_binding_kind=runtime.activation_binding_kind
                 AND gb.activation_binding_digest=runtime.activation_binding_digest
                 AND g.provider_id=?10 AND g.credential_realm=?10
                 AND g.profile_digest=admission.profile_digest
                 AND g.pricing_revision_digest=admission.pricing_revision_digest)))",
        params![claim.attempt_id.as_bytes().as_slice(), claim.provider_idempotency_key,
            claim.permit_id.as_slice(), claim.prepared_digest.as_slice(), claim.render_digest.as_slice(),
            claim.profile_digest.as_slice(), i64::try_from(claim.fencing_token).map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            claim.token_reservation_id.as_slice(), claim.cost_reservation_id.as_slice(), claim.provider_id.as_str(), observed],
        |row| row.get(0),
    ).map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if !valid {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    super::readback::verify_final_send(transaction, claim, proof, observed)
}
