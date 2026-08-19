use runne_application::provider::{
    ProviderOperationalTelemetryScope, ProviderOperationalTelemetrySourceError,
};
use rusqlite::Transaction;

use super::TelemetryResult;
use super::aggregates::candidate_bindings;
use super::guards;
use super::runtime::value;

pub(super) fn read(
    transaction: &Transaction<'_>,
    scope: &ProviderOperationalTelemetryScope,
) -> TelemetryResult<u64> {
    guards::uncertain(transaction)?;
    let count: i64 = transaction
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
         )
         SELECT COUNT(*) FROM provider_dispatch_attempts dispatch
         JOIN provider_execution_admissions admission
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
         WHERE dispatch.state = 6
           AND admission.generation <= runtime.expected_generation",
            rusqlite::params_from_iter(candidate_bindings(scope)?),
            |row| row.get(0),
        )
        .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?;
    value(count)
}
