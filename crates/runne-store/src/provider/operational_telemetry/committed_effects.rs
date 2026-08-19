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
    guards::effects(transaction)?;
    transaction
        .query_row(
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
             SELECT effect.effect_expires_at AS expires_at
             FROM provider_effect_starts effect
             JOIN provider_execution_admissions admission
               ON effect.dispatch_attempt_id = admission.dispatch_attempt_id
              AND effect.provider_idempotency_key = admission.provider_idempotency_key
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
             WHERE effect.dispatch_attempt_id = dispatch.attempt_id
               AND effect.provider_idempotency_key = dispatch.provider_idempotency_key
               AND effect.permit_id = dispatch.permit_id
               AND effect.state = 1
               AND effect.effect_expires_at = effect.effect_started_at + 120
               AND dispatch.state IN (1, 3, 4, 6)
               AND admission.generation <= runtime.expected_generation
               AND ((dispatch.state IN (1, 3, 4)
                     AND admission.generation = runtime.expected_generation
                     AND admission.fencing_token = runtime.expected_fencing_token)
                    OR dispatch.state = 6)
         )
         SELECT COUNT(*) AS active_count,
                COALESCE(SUM(CASE WHEN expires_at <= :observed_at THEN 1 ELSE 0 END), 0)
                  AS expired_active_count,
                MIN(CASE WHEN expires_at > :observed_at THEN expires_at END)
                  AS nearest_unexpired_expiry_unix_seconds
         FROM candidates",
            rusqlite::params_from_iter(bindings(scope)?),
            aggregate,
        )
        .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)
}
