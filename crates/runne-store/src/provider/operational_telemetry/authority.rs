use runne_application::provider::{
    ProviderOperationalExpiryAggregate, ProviderOperationalTelemetryScope,
    ProviderOperationalTelemetrySourceError,
};
use rusqlite::Transaction;

use super::TelemetryResult;
use super::aggregates::{aggregate, bindings};
use super::guards;

pub(super) fn read(
    transaction: &Transaction<'_>,
    scope: &ProviderOperationalTelemetryScope,
) -> TelemetryResult<ProviderOperationalExpiryAggregate> {
    guards::authority(transaction, scope)?;
    transaction.query_row(
        "WITH runtime AS (
             SELECT * FROM provider_runtime_authority_state runtime
             WHERE runtime.id = 1 AND runtime.active = 1
               AND runtime.runtime_authority_id = :runtime_authority_id
               AND runtime.database_generation = :database_generation
               AND runtime.expected_generation = :launch_generation
               AND runtime.lease_generation = :launch_generation
               AND runtime.expected_fencing_token = :fencing_token
               AND runtime.lease_fencing_token = :fencing_token
               AND runtime.profile_digest = :profile_digest
         ), candidates AS (
             SELECT authority.expires_at AS expires_at
             FROM provider_effect_authorities authority
             JOIN provider_execution_admissions admission
               ON admission.authority_id = authority.authority_id
              AND admission.authority_revision = authority.revision
              AND authority.attempt_id = admission.dispatch_attempt_id
              AND authority.permit_id = admission.permit_id
              AND authority.capability_grant_id = admission.capability_grant_id
              AND authority.token_reservation_id = admission.token_reservation_id
              AND authority.cost_reservation_id = admission.cost_reservation_id
              AND authority.prepared_digest = admission.prepared_digest
              AND authority.render_digest = admission.render_digest
              AND authority.profile_digest = admission.profile_digest
              AND authority.owner_id = admission.owner_id
              AND authority.scope = admission.scope
              AND authority.fencing_token = admission.fencing_token
              AND authority.expires_at = admission.expires_at
             JOIN provider_dispatch_attempts dispatch
               ON dispatch.attempt_id = admission.dispatch_attempt_id
              AND dispatch.call_id = admission.call_id
              AND dispatch.permit_id = admission.permit_id
              AND dispatch.token_reservation_id = admission.token_reservation_id
              AND dispatch.cost_reservation_id = admission.cost_reservation_id
              AND dispatch.fencing_token = admission.fencing_token
              AND dispatch.provider_idempotency_key = admission.provider_idempotency_key
              AND dispatch.prepared_digest = admission.prepared_digest
              AND dispatch.render_digest = admission.render_digest
              AND dispatch.profile_digest = admission.profile_digest
             JOIN runtime ON admission.runtime_authority_id = runtime.runtime_authority_id
              AND admission.database_generation = runtime.database_generation
              AND admission.profile_digest = runtime.profile_digest
              AND admission.generation = runtime.expected_generation
              AND admission.fencing_token = runtime.expected_fencing_token
              AND admission.principal_id = runtime.principal_id
              AND admission.owner_id = runtime.owner_id
              AND admission.scope = runtime.scope
              AND admission.capability_grant_id = runtime.capability_grant_id
              AND admission.capability_revision = runtime.capability_revision
              AND admission.capability_expires_at = runtime.capability_expires_at
              AND admission.capability_revocation_epoch = runtime.capability_revocation_epoch
              AND admission.capability_revocation_observed = runtime.capability_revocation_observed
              AND admission.approval_id = runtime.approval_id
              AND admission.approval_revision = runtime.approval_revision
              AND admission.approval_expires_at = runtime.approval_expires_at
              AND admission.approval_revocation_epoch = runtime.approval_revocation_epoch
              AND admission.approval_revocation_observed = runtime.approval_revocation_observed
              AND admission.pricing_revision_digest = runtime.pricing_revision_digest
              AND admission.activation_binding_kind = runtime.activation_binding_kind
              AND admission.activation_binding_digest = runtime.activation_binding_digest
             WHERE authority.revoked = 0 AND authority.consumed = 1
               AND authority.consumed_intent_id = ('provider:' || lower(hex(admission.dispatch_attempt_id)))
               AND dispatch.state = 1 AND runtime.capability_allowed = 1
               AND runtime.approval_allowed = 1
               AND runtime.capability_revocation_observed = 0
               AND runtime.approval_revocation_observed = 0
               AND NOT EXISTS (SELECT 1 FROM provider_effect_starts effect
                               WHERE effect.dispatch_attempt_id = dispatch.attempt_id)
         )
         SELECT COUNT(*) AS active_count,
                COALESCE(SUM(CASE WHEN expires_at <= :observed_at THEN 1 ELSE 0 END), 0)
                  AS expired_active_count,
                MIN(CASE WHEN expires_at > :observed_at THEN expires_at END)
                  AS nearest_unexpired_expiry_unix_seconds
         FROM candidates",
        rusqlite::params_from_iter(bindings(scope)?), aggregate,
    ).map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)
}
