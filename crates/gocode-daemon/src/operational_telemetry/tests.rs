use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use gocode_api::{
    OperationalTelemetryQueryPort, RecoveryObservationStatusV1, TelemetryCompletenessV1,
};
use gocode_application::ports::{Clock, ClockError};
use gocode_application::provider::{
    ProviderDurableOperationalTelemetry, ProviderOperationalTelemetryScope,
    ProviderOperationalTelemetrySource, ProviderOperationalTelemetrySourceError,
};
use gocode_domain::timestamp::Timestamp;
use gocode_observability::operational::RecoveryObservationRegistry;

use super::*;

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Result<Timestamp, ClockError> {
        Ok(Timestamp::from_unix_micros(1_000_000))
    }
}

struct EmptyDurableSource;

impl ProviderOperationalTelemetrySource for EmptyDurableSource {
    fn read_durable_operational_telemetry(
        &self,
        _: ProviderOperationalTelemetryScope,
    ) -> Result<ProviderDurableOperationalTelemetry, ProviderOperationalTelemetrySourceError> {
        Ok(ProviderDurableOperationalTelemetry::new(
            None, None, None, None, None,
        ))
    }
}

struct MarkerFailingSource {
    mapped: Arc<AtomicBool>,
}

impl ProviderOperationalTelemetrySource for MarkerFailingSource {
    fn read_durable_operational_telemetry(
        &self,
        _: ProviderOperationalTelemetryScope,
    ) -> Result<ProviderDurableOperationalTelemetry, ProviderOperationalTelemetrySourceError> {
        let marker = "task3-path-marker";
        let directory = tempfile::tempdir().expect("temporary marker path");
        let path = directory.path().join(marker).join("telemetry.sqlite");
        let raw = rusqlite::Connection::open(&path).expect_err("missing marker parent must fail");
        Err(map_raw_sqlite_error(raw, marker, &self.mapped))
    }
}

fn map_raw_sqlite_error(
    raw: rusqlite::Error,
    marker: &str,
    mapped: &AtomicBool,
) -> ProviderOperationalTelemetrySourceError {
    assert!(format!("{raw:?}").contains(marker) || raw.to_string().contains(marker));
    mapped.store(true, Ordering::SeqCst);
    drop(raw);
    ProviderOperationalTelemetrySourceError::Unavailable
}

#[test]
fn available_empty_durable_source_produces_unavailable_section_not_query_error() {
    let (registry, _) = RecoveryObservationRegistry::new();
    let service = DaemonOperationalTelemetryQueryService::new_for_test(
        Arc::new(EmptyDurableSource),
        Arc::new(registry),
        Arc::new(FixedClock),
        match DaemonTelemetryLaunchContext::from_retained_fields([1; 16], 1, 7, 7, [2; 32], 7) {
            Ok(launch) => launch,
            Err(_) => panic!("test launch context must be valid"),
        },
    );

    let snapshot = service.query_operational_telemetry().unwrap();

    assert!(matches!(
        snapshot.durable().meta().completeness(),
        TelemetryCompletenessV1::Unavailable
    ));
    assert!(matches!(
        snapshot.recovery_transient().status(),
        RecoveryObservationStatusV1::LowerBoundSinceLaunch
    ));
}

#[test]
fn marker_bearing_raw_store_diagnostic_maps_to_fieldless_daemon_error() {
    let (registry, _) = RecoveryObservationRegistry::new();
    let mapped = Arc::new(AtomicBool::new(false));
    let service = DaemonOperationalTelemetryQueryService::new_for_test(
        Arc::new(MarkerFailingSource {
            mapped: Arc::clone(&mapped),
        }),
        Arc::new(registry),
        Arc::new(FixedClock),
        match DaemonTelemetryLaunchContext::from_retained_fields([1; 16], 1, 7, 7, [2; 32], 7) {
            Ok(launch) => launch,
            Err(_) => panic!("test launch context must be valid"),
        },
    );
    let error = match service.query_operational_telemetry() {
        Ok(_) => panic!("marker-bearing source must be unavailable"),
        Err(error) => error,
    };
    let marker = "task3-path-marker";
    assert!(mapped.load(Ordering::SeqCst));
    assert!(!format!("{error:?}").contains(marker));
    assert!(!error.to_string().contains(marker));
}
