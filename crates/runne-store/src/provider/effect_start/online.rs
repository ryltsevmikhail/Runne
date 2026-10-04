use super::online_helpers::{encode_hex, online_clock_error, online_sql_error};
use super::online_proof::verify_issuance;
use super::online_receipt::ProviderOnlineEffectStartReceipt;
use crate::provider::ProviderRuntimeLaunchCapability;
use crate::provider::execution_store::online_effect_proof::{
    CommittedEffectProofFields, OnlineEffectProofState,
};
use crate::provider::{OnlineEffectStartBinding, credential_lifecycle};
use crate::schema::ManagedConnection;
use runne_application::provider::ProviderAdmissionError;
use runne_provider::ProviderDispatchClaim;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

mod final_send;
mod readback;
pub(super) use final_send::verify_final_send;

pub(crate) fn start_online_effect(
    connection: &mut ManagedConnection,
    launch: &ProviderRuntimeLaunchCapability,
    claim: &ProviderDispatchClaim,
    binding: &OnlineEffectStartBinding,
    proof_state: &OnlineEffectProofState,
    now: impl Fn() -> i64,
    fail_readback: bool,
) -> Result<ProviderOnlineEffectStartReceipt, ProviderAdmissionError> {
    if claim.provider_id != *binding.provider() {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    let proof = proof_state.lock()?;
    let proof = proof
        .as_ref()
        .ok_or(ProviderAdmissionError::AuthorityDenied)?;
    proof.ensure_current_active(&transaction)?;
    launch.verify_current_admission(&transaction, claim)?;
    crate::store::taskrun_provider_start::verify_admitted_running_attempt(
        &transaction,
        claim.attempt_id.as_bytes(),
    )
    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
    let observed = now();
    credential_lifecycle::advance_provider_clock(&transaction, binding.provider(), observed)
        .map_err(online_clock_error)?;
    let issuance = verify_issuance(&transaction, claim, proof)?;
    let lease: Option<(Vec<u8>, i64, i64)> = transaction.query_row(
        "SELECT mirror.lease_owner, mirror.lease_expires_at, mirror.lease_fencing_token
            FROM provider_execution_admissions admission
            JOIN provider_dispatch_attempts dispatch ON dispatch.attempt_id=admission.dispatch_attempt_id
            JOIN provider_online_dispatch_claim_providers claim_provider
              ON claim_provider.dispatch_attempt_id=admission.dispatch_attempt_id
            JOIN provider_runtime_authority_state runtime ON runtime.id=1
            JOIN provider_effect_authorities authority ON authority.authority_id=admission.authority_id
              AND authority.revision=admission.authority_revision
            JOIN provider_credential_authority_heads head ON head.provider_id=?11
            JOIN provider_credential_versions mirror ON mirror.provider_id=head.provider_id
              AND mirror.credential_version=head.active_credential_version
              AND mirror.ref_digest=head.active_ref_digest
            WHERE admission.dispatch_attempt_id=?1 AND admission.permit_id=?2
              AND admission.provider_idempotency_key=?3 AND admission.prepared_digest=?4
              AND admission.render_digest=?5 AND admission.profile_digest=?6
              AND admission.fencing_token=?7 AND admission.token_reservation_id=?9
              AND admission.cost_reservation_id=?10 AND dispatch.state=1
              AND dispatch.permit_id=?2 AND dispatch.prepared_digest=?4
              AND dispatch.render_digest=?5 AND dispatch.profile_digest=?6
              AND dispatch.fencing_token=?7 AND dispatch.token_reservation_id=?9
              AND dispatch.cost_reservation_id=?10 AND runtime.active=1
              AND runtime.expected_generation=runtime.lease_generation
              AND runtime.expected_fencing_token=runtime.lease_fencing_token
              AND runtime.runtime_authority_id=admission.runtime_authority_id
              AND runtime.database_generation=admission.database_generation
              AND runtime.expected_generation=admission.generation
              AND runtime.expected_fencing_token=admission.fencing_token
              AND runtime.principal_id=admission.principal_id AND runtime.owner_id=admission.owner_id
              AND runtime.scope=admission.scope AND runtime.capability_grant_id=admission.capability_grant_id
              AND runtime.capability_revision=admission.capability_revision
              AND runtime.capability_expires_at=admission.capability_expires_at
              AND runtime.capability_revocation_epoch=admission.capability_revocation_epoch
              AND runtime.capability_revocation_observed=admission.capability_revocation_observed
              AND runtime.approval_id=admission.approval_id AND runtime.approval_revision=admission.approval_revision
              AND runtime.approval_expires_at=admission.approval_expires_at
              AND runtime.approval_revocation_epoch=admission.approval_revocation_epoch
              AND runtime.approval_revocation_observed=admission.approval_revocation_observed
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
                      AND grant_row.provider_id=?11
                      AND grant_row.credential_realm=?11
                      AND grant_row.profile_digest=admission.profile_digest
                      AND grant_row.pricing_revision_digest=admission.pricing_revision_digest)
              )
              AND runtime.activation_binding_kind=admission.activation_binding_kind
              AND runtime.activation_binding_digest=admission.activation_binding_digest
              AND runtime.capability_allowed=1 AND runtime.approval_allowed=1
              AND runtime.capability_expires_at>?8 AND runtime.approval_expires_at>?8
              AND authority.attempt_id=admission.dispatch_attempt_id AND authority.permit_id=admission.permit_id
              AND authority.token_reservation_id=admission.token_reservation_id
              AND authority.cost_reservation_id=admission.cost_reservation_id
              AND authority.prepared_digest=admission.prepared_digest AND authority.render_digest=admission.render_digest
              AND authority.profile_digest=admission.profile_digest AND authority.fencing_token=admission.fencing_token
              AND authority.expires_at>?8 AND authority.revoked=0 AND authority.consumed=1
              AND authority.consumed_intent_id=('provider:' || lower(hex(admission.dispatch_attempt_id)))
              AND EXISTS(SELECT 1 FROM provider_budget_reservations budget
                         WHERE budget.provider_idempotency_key=admission.provider_idempotency_key
                           AND budget.dimension=1 AND budget.reservation_id=admission.token_reservation_id
                           AND budget.state=1)
              AND EXISTS(SELECT 1 FROM provider_budget_reservations budget
                         WHERE budget.provider_idempotency_key=admission.provider_idempotency_key
                           AND budget.dimension=2 AND budget.reservation_id=admission.cost_reservation_id
                           AND budget.state=1)
              AND head.lifecycle_revision=?12 AND head.credential_fence=?13
              AND claim_provider.provider_id=?11
              AND head.active_credential_version=?14 AND head.active_ref_digest=?15
              AND head.hard_fence_disposition IS NULL AND head.release_migration_state IN ('NONE','CLEARED')
              AND mirror.lifecycle_state='ACTIVE' AND mirror.revocation_fence < mirror.lease_fencing_token
              AND mirror.lease_expires_at>?8",
        params![
            claim.attempt_id.as_bytes().as_slice(), claim.permit_id.as_slice(),
            claim.provider_idempotency_key, claim.prepared_digest.as_slice(), claim.render_digest.as_slice(),
            claim.profile_digest.as_slice(), i64::try_from(claim.fencing_token).map_err(|_| ProviderAdmissionError::StaleFencingToken)?,
            observed, claim.token_reservation_id.as_slice(), claim.cost_reservation_id.as_slice(),
            binding.provider().as_str(), i64::try_from(binding.lifecycle_revision()).map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            i64::try_from(binding.credential_fence()).map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            i64::try_from(binding.active().version()).map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            binding.active().ref_digest().as_slice(),
        ], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()
    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    let (lease_owner, lease_expires_at, lease_fence) =
        lease.ok_or(ProviderAdmissionError::AuthorityDenied)?;
    let lease_owner: [u8; 16] = lease_owner
        .try_into()
        .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
    let lease_fence =
        u64::try_from(lease_fence).map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
    let expires = observed
        .checked_add(120)
        .ok_or(ProviderAdmissionError::AuthorityDenied)?;
    let effect_fields = CommittedEffectProofFields {
        issuance_mac: issuance.mac,
        attempt_id: *claim.attempt_id.as_bytes(),
        provider_id: binding.provider().as_str().to_owned(),
        launch_generation: binding.launch_generation(),
        lifecycle_revision: binding.lifecycle_revision(),
        credential_fence: binding.credential_fence(),
        credential_version: binding.active().version(),
        credential_ref_digest: *binding.active().ref_digest(),
        lease_owner,
        lease_expires_at,
        lease_fence,
        effect_started_at: observed,
        effect_expires_at: expires,
    };
    let effect_mac = proof.effect(issuance.binding, &effect_fields)?;
    transaction.execute(
        "INSERT INTO provider_effect_starts (dispatch_attempt_id, provider_idempotency_key, permit_id, effect_started_at, effect_expires_at, state)
         VALUES (?1, ?2, ?3, ?4, ?5, 1)",
        params![claim.attempt_id.as_bytes().as_slice(), claim.provider_idempotency_key, claim.permit_id.as_slice(), observed, expires],
    )
    .map_err(online_sql_error)?;
    transaction.execute(
        "INSERT INTO provider_online_credential_effect_bindings
         (dispatch_attempt_id, provider_id, launch_generation, lifecycle_revision, credential_fence, active_credential_version, active_ref_digest, effect_mac)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![claim.attempt_id.as_bytes().as_slice(), binding.provider().as_str(),
            i64::try_from(binding.launch_generation()).map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            i64::try_from(binding.lifecycle_revision()).map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            i64::try_from(binding.credential_fence()).map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            i64::try_from(binding.active().version()).map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            binding.active().ref_digest().as_slice(), effect_mac.as_slice()],
    )
    .map_err(online_sql_error)?;
    let intent_id = format!("provider:{}", encode_hex(claim.attempt_id.as_bytes()));
    transaction
        .execute(
            "INSERT INTO security_audit_pre_effect (intent_id, side_effect_started) VALUES (?1, 1)",
            [&intent_id],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    transaction
        .commit()
        .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
    #[cfg(feature = "test-support")]
    crate::store::commit_gate::note_kill_boundary("b3_post_effect_start_commit");
    if fail_readback {
        return Err(ProviderAdmissionError::PostClaimUncertain);
    }
    readback::load(connection, claim, proof, observed, expires, now)
}
