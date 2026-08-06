use std::sync::Arc;

use gocode_application::provider::{
    ProviderDurableOperationalTelemetry, ProviderOperationalTelemetryScope,
    ProviderOperationalTelemetrySource, ProviderOperationalTelemetrySourceError,
};
use gocode_store::provider::SqliteProviderExecutionStore;

pub(super) enum OperationalTelemetryStore {
    Sqlite(Arc<SqliteProviderExecutionStore>),
    #[cfg(test)]
    Source(Arc<dyn ProviderOperationalTelemetrySource>),
}

impl OperationalTelemetryStore {
    pub(super) fn read(
        &self,
        scope: ProviderOperationalTelemetryScope,
    ) -> Result<ProviderDurableOperationalTelemetry, ProviderOperationalTelemetrySourceError> {
        match self {
            Self::Sqlite(store) => store.read_durable_operational_telemetry(scope),
            #[cfg(test)]
            Self::Source(source) => source.read_durable_operational_telemetry(scope),
        }
    }
}
