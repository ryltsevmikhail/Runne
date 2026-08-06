use gocode_application::provider::{
    ProviderOperationalExpiryAggregate, ProviderOperationalTelemetryScope,
    ProviderOperationalTelemetrySourceError,
};
use rusqlite::{Row, Transaction};

use super::TelemetryResult;
use super::guards;
use super::runtime::{integer, value};

pub(super) fn read_approval(
    transaction: &Transaction<'_>,
    scope: &ProviderOperationalTelemetryScope,
) -> TelemetryResult<ProviderOperationalExpiryAggregate> {
    guards::approval(transaction)?;
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
             SELECT runtime.approval_expires_at AS expires_at FROM runtime
             WHERE runtime.approval_allowed = 1
               AND runtime.approval_revocation_observed = 0
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

pub(super) fn bindings(
    scope: &ProviderOperationalTelemetryScope,
) -> TelemetryResult<Vec<rusqlite::types::Value>> {
    let mut bindings = candidate_bindings(scope)?;
    bindings.push(integer(scope.observed_at_unix_seconds())?.into());
    Ok(bindings)
}

pub(super) fn candidate_bindings(
    scope: &ProviderOperationalTelemetryScope,
) -> TelemetryResult<Vec<rusqlite::types::Value>> {
    Ok(vec![
        scope.runtime_authority_id().to_vec().into(),
        integer(scope.database_generation())?.into(),
        integer(scope.launch_generation())?.into(),
        integer(scope.fencing_token())?.into(),
        scope.profile_digest().to_vec().into(),
    ])
}

pub(super) fn aggregate(row: &Row<'_>) -> rusqlite::Result<ProviderOperationalExpiryAggregate> {
    let active: i64 = row.get(0)?;
    let expired: i64 = row.get(1)?;
    let nearest: Option<i64> = row.get(2)?;
    ProviderOperationalExpiryAggregate::new(
        value(active).map_err(|_| rusqlite::Error::InvalidQuery)?,
        value(expired).map_err(|_| rusqlite::Error::InvalidQuery)?,
        nearest
            .map(value)
            .transpose()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)
}
