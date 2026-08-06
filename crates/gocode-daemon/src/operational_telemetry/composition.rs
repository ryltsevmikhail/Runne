use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use gocode_api::OperationalTelemetryQueryPort;
use gocode_application::ports::{Clock, ClockError};
use gocode_domain::timestamp::Timestamp;

use super::{
    DaemonOperationalTelemetryClock, DaemonOperationalTelemetryQueryService,
    unavailable_operational_telemetry_query,
};
use crate::canonical_provider::DaemonCanonicalOpenAiService;

pub(crate) fn compose_operational_telemetry_query(
    provider_service: Option<&Arc<DaemonCanonicalOpenAiService>>,
    authenticated_launch_generation: u64,
) -> Arc<dyn OperationalTelemetryQueryPort> {
    let Some(provider_service) = provider_service else {
        return unavailable_operational_telemetry_query();
    };
    let Ok(launch) = provider_service.telemetry_launch_context(authenticated_launch_generation)
    else {
        return unavailable_operational_telemetry_query();
    };
    let production_wall_clock = || {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::Unavailable)?
            .as_micros();
        let micros = i64::try_from(micros).map_err(|_| ClockError::Unavailable)?;
        Ok(Timestamp::from_unix_micros(micros))
    };
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(DaemonOperationalTelemetryClock::new(
        Arc::new(production_wall_clock),
    ));
    Arc::new(DaemonOperationalTelemetryQueryService::new(
        provider_service.operational_telemetry_store(),
        provider_service.recovery_observation_registry(),
        clock,
        launch,
    ))
}
