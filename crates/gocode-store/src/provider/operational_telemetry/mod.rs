mod accounting;
mod aggregates;
mod authority;
mod committed_effects;
mod guards;
mod runtime;
mod uncertain;

use gocode_application::provider::{
    ProviderDurableOperationalTelemetry, ProviderOperationalTelemetryScope,
    ProviderOperationalTelemetrySource, ProviderOperationalTelemetrySourceError,
};
use rusqlite::TransactionBehavior;

use super::SqliteProviderExecutionStore;

type TelemetryResult<T> = Result<T, ProviderOperationalTelemetrySourceError>;

impl ProviderOperationalTelemetrySource for SqliteProviderExecutionStore {
    fn read_durable_operational_telemetry(
        &self,
        scope: ProviderOperationalTelemetryScope,
    ) -> TelemetryResult<ProviderDurableOperationalTelemetry> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?;
        runtime::read(&transaction, &scope)?;
        let accounting = accounting::read(&transaction, &scope).ok();
        let authorities = authority::read(&transaction, &scope).ok();
        let approval = aggregates::read_approval(&transaction, &scope).ok();
        let effects = committed_effects::read(&transaction, &scope).ok();
        let uncertain = uncertain::read(&transaction, &scope).ok();
        transaction
            .commit()
            .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?;
        Ok(ProviderDurableOperationalTelemetry::new(
            accounting,
            authorities,
            approval,
            effects,
            uncertain,
        ))
    }
}
