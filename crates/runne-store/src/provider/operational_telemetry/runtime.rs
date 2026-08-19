use runne_application::provider::{
    ProviderOperationalTelemetryScope, ProviderOperationalTelemetrySourceError,
};
use rusqlite::{Transaction, params};

use super::TelemetryResult;

pub(super) fn read(
    transaction: &Transaction<'_>,
    scope: &ProviderOperationalTelemetryScope,
) -> TelemetryResult<()> {
    transaction
        .query_row(
            "SELECT 1
         FROM provider_runtime_authority_state runtime
         WHERE runtime.id = 1 AND runtime.active = 1
           AND runtime.runtime_authority_id = :runtime_authority_id
           AND runtime.database_generation = :database_generation
           AND runtime.expected_generation = :launch_generation
           AND runtime.lease_generation = :launch_generation
           AND runtime.expected_fencing_token = :fencing_token
           AND runtime.lease_fencing_token = :fencing_token
           AND runtime.profile_digest = :profile_digest",
            params![
                scope.runtime_authority_id().as_slice(),
                integer(scope.database_generation())?,
                integer(scope.launch_generation())?,
                integer(scope.fencing_token())?,
                scope.profile_digest().as_slice(),
            ],
            |_| Ok(()),
        )
        .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)
}

pub(super) fn integer(value: u64) -> TelemetryResult<i64> {
    i64::try_from(value).map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)
}

pub(super) fn value(value: i64) -> TelemetryResult<u64> {
    u64::try_from(value).map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)
}
