use std::sync::Arc;

use runne_api::{
    OperationalTelemetryQueryErrorV1, OperationalTelemetryQueryPort,
    RuntimeOperationalTelemetrySnapshotV1,
};

struct UnavailableOperationalTelemetryQuery;

impl OperationalTelemetryQueryPort for UnavailableOperationalTelemetryQuery {
    fn query_operational_telemetry(
        &self,
    ) -> Result<RuntimeOperationalTelemetrySnapshotV1, OperationalTelemetryQueryErrorV1> {
        Err(OperationalTelemetryQueryErrorV1::Unavailable)
    }
}

pub(crate) fn unavailable_operational_telemetry_query() -> Arc<dyn OperationalTelemetryQueryPort> {
    Arc::new(UnavailableOperationalTelemetryQuery)
}
