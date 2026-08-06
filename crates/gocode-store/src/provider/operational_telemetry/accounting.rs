use gocode_application::provider::{
    ProviderOperationalAccounting, ProviderOperationalTelemetryScope,
    ProviderOperationalTelemetrySourceError,
};
use rusqlite::{Transaction, params};

use super::TelemetryResult;
use super::runtime::integer;

pub(super) fn read(
    transaction: &Transaction<'_>,
    scope: &ProviderOperationalTelemetryScope,
) -> TelemetryResult<ProviderOperationalAccounting> {
    let values: (i64, i64, i64, i64, i64, i64) = transaction
        .query_row(
            "SELECT token_budget_limit, token_budget_reserved, token_budget_settled,
                cost_budget_limit_micros, cost_budget_reserved_micros, cost_budget_settled_micros
         FROM provider_runtime_authority_state runtime
         WHERE runtime.id = 1 AND runtime.active = 1
           AND runtime.runtime_authority_id = ?1
           AND runtime.database_generation = ?2
           AND runtime.expected_generation = ?3
           AND runtime.lease_generation = ?3
           AND runtime.expected_fencing_token = ?4
           AND runtime.lease_fencing_token = ?4
           AND runtime.profile_digest = ?5",
            params![
                scope.runtime_authority_id().as_slice(),
                integer(scope.database_generation())?,
                integer(scope.launch_generation())?,
                integer(scope.fencing_token())?,
                scope.profile_digest().as_slice()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?;
    let non_usd: i64 = transaction
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
         SELECT EXISTS(
             SELECT 1 FROM provider_execution_admissions admission JOIN runtime
               ON admission.runtime_authority_id = runtime.runtime_authority_id
              AND admission.database_generation = runtime.database_generation
              AND admission.profile_digest = runtime.profile_digest
              AND admission.generation = runtime.expected_generation
              AND admission.fencing_token = runtime.expected_fencing_token
             WHERE admission.currency <> 'USD'
             UNION ALL
             SELECT 1 FROM provider_accounting_settlements settlement
             JOIN provider_dispatch_attempts dispatch
               ON settlement.dispatch_attempt_id = dispatch.attempt_id
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
              AND admission.generation = runtime.expected_generation
              AND admission.fencing_token = runtime.expected_fencing_token
             WHERE settlement.currency <> 'USD'
         )",
            params![
                scope.runtime_authority_id().as_slice(),
                integer(scope.database_generation())?,
                integer(scope.launch_generation())?,
                integer(scope.fencing_token())?,
                scope.profile_digest().as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?;
    if non_usd != 0 {
        return Err(ProviderOperationalTelemetrySourceError::Unavailable);
    }
    ProviderOperationalAccounting::new(
        u64::try_from(values.0)
            .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?,
        u64::try_from(values.1)
            .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?,
        u64::try_from(values.2)
            .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?,
        u64::try_from(values.3)
            .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?,
        u64::try_from(values.4)
            .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?,
        u64::try_from(values.5)
            .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?,
    )
}
