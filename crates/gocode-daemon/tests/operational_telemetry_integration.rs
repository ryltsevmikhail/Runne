use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
#[path = "operational_telemetry_integration/task12_security.rs"]
mod task12_security;
#[cfg(unix)]
#[path = "operational_telemetry_integration/tls_session.rs"]
mod tls_session;
#[cfg(unix)]
#[path = "operational_telemetry_integration/tls_status.rs"]
mod tls_status;

use gocode_api::{
    OPERATIONAL_TELEMETRY_SCHEMA_VERSION_V1, OperationalTelemetryQueryErrorV1,
    OperationalTelemetryQueryPort, RecoveryObservationStatusV1, TelemetryCompletenessV1,
};
use gocode_application::ports::{Clock, ClockError};
use gocode_application::provider::{ProviderLeaseBindingKind, ProviderRecoveryObserver};
use gocode_daemon::operational_telemetry::{
    DaemonOperationalTelemetryQueryService, DaemonTelemetryLaunchContext,
};
use gocode_domain::timestamp::Timestamp;
use gocode_observability::operational::RecoveryObservationRegistry;
use gocode_store::provider::{ProviderRuntimeAuthorityConfig, SqliteProviderExecutionStore};

const AUTHORITY: [u8; 16] = [1; 16];
const PROFILE: [u8; 32] = [2; 32];
const GENERATION: u64 = 7;
const FENCE: u64 = 13;

struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Result<Timestamp, ClockError> {
        Ok(self.0)
    }
}

struct FailingClock;

impl Clock for FailingClock {
    fn now(&self) -> Result<Timestamp, ClockError> {
        Err(ClockError::Unavailable)
    }
}

struct SequenceClock(Mutex<VecDeque<Timestamp>>);

impl Clock for SequenceClock {
    fn now(&self) -> Result<Timestamp, ClockError> {
        self.0
            .lock()
            .map_err(|_| ClockError::Unavailable)?
            .pop_front()
            .ok_or(ClockError::Unavailable)
    }
}

fn store() -> (tempfile::TempDir, Arc<SqliteProviderExecutionStore>) {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        SqliteProviderExecutionStore::open(&directory.path().join("telemetry.sqlite")).unwrap(),
    );
    store
        .install_runtime_authority_and_advance_worker_lease(&ProviderRuntimeAuthorityConfig {
            runtime_authority_id: AUTHORITY,
            database_generation: 1,
            principal_id: "principal".into(),
            owner_id: "owner".into(),
            scope: "provider.dispatch".into(),
            generation: GENERATION,
            fencing_token: FENCE,
            capability_grant_id: "capability".into(),
            capability_revision: 1,
            capability_allowed: true,
            capability_revocation_epoch: 1,
            approval_id: "approval".into(),
            approval_revision: 1,
            approval_allowed: true,
            approval_revocation_epoch: 1,
            profile_digest: PROFILE,
            pricing_revision_digest: [3; 32],
            activation_binding_kind: ProviderLeaseBindingKind::ProtectedV2,
            activation_binding_digest: [4; 32],
            token_budget_limit: 10_000,
            cost_budget_limit_micros: 1_000_000,
            authority_ttl_seconds: 120,
            lease_ttl_seconds: 600,
        })
        .unwrap();
    (directory, store)
}

fn context(authenticated_generation: u64) -> DaemonTelemetryLaunchContext {
    match DaemonTelemetryLaunchContext::from_retained_fields(
        AUTHORITY,
        1,
        GENERATION,
        FENCE,
        PROFILE,
        authenticated_generation,
    ) {
        Ok(context) => context,
        Err(_) => panic!("test launch context must be valid"),
    }
}

fn make_service<C: Clock + Send + Sync + 'static>(
    store: Arc<SqliteProviderExecutionStore>,
    registry: Arc<RecoveryObservationRegistry>,
    clock: C,
) -> DaemonOperationalTelemetryQueryService {
    DaemonOperationalTelemetryQueryService::new(
        store,
        registry,
        Arc::new(clock),
        context(GENERATION),
    )
}

#[test]
fn service_maps_complete_durable_data_and_complete_recovery_with_fixed_observed_at() {
    let (_directory, store) = store();
    let (registry, observer) = RecoveryObservationRegistry::new();
    observer.observe_recovered_terminal_output().unwrap();
    let service = make_service(
        store,
        Arc::new(registry),
        FixedClock(Timestamp::from_unix_micros(1_234_567)),
    );

    let snapshot = service.query_operational_telemetry().unwrap();

    assert_eq!(snapshot.launch_generation(), GENERATION);
    assert_eq!(
        snapshot.schema_version(),
        OPERATIONAL_TELEMETRY_SCHEMA_VERSION_V1
    );
    assert_eq!(snapshot.observed_at_unix_seconds(), 1);
    assert!(matches!(
        snapshot.durable().meta().completeness(),
        TelemetryCompletenessV1::Complete
    ));
    assert!(matches!(
        snapshot.recovery_transient().status(),
        RecoveryObservationStatusV1::LowerBoundSinceLaunch
    ));
    assert_eq!(
        snapshot
            .recovery_transient()
            .observed_outbox_recoveries_in_generation(),
        Some(1)
    );
}

#[test]
fn service_maps_truncated_and_unavailable_recovery_statuses() {
    let (_directory, store) = store();
    let (registry, observer) = RecoveryObservationRegistry::new();
    for _ in 0..65 {
        let _ = observer.observe_recovered_terminal_output();
    }
    let service = make_service(
        Arc::clone(&store),
        Arc::new(registry),
        FixedClock(Timestamp::from_unix_micros(2_000_000)),
    );
    assert!(matches!(
        service
            .query_operational_telemetry()
            .unwrap()
            .recovery_transient()
            .status(),
        RecoveryObservationStatusV1::TruncatedLowerBoundSinceLaunch
    ));

    let (registry, _) = RecoveryObservationRegistry::new();
    registry.close();
    let unavailable = make_service(
        store,
        Arc::new(registry),
        FixedClock(Timestamp::from_unix_micros(2_000_000)),
    );
    assert!(matches!(
        unavailable
            .query_operational_telemetry()
            .unwrap()
            .recovery_transient()
            .status(),
        RecoveryObservationStatusV1::Unavailable
    ));
}

#[test]
fn service_maps_clock_failure_and_negative_timestamp_to_static_unavailable() {
    let (_directory, store) = store();
    let (registry, _) = RecoveryObservationRegistry::new();
    let failing = make_service(Arc::clone(&store), Arc::new(registry), FailingClock);
    assert!(matches!(
        failing.query_operational_telemetry(),
        Err(OperationalTelemetryQueryErrorV1::Unavailable)
    ));

    let (registry, _) = RecoveryObservationRegistry::new();
    let negative = make_service(
        store,
        Arc::new(registry),
        FixedClock(Timestamp::from_unix_micros(-1)),
    );
    assert!(matches!(
        negative.query_operational_telemetry(),
        Err(OperationalTelemetryQueryErrorV1::Unavailable)
    ));
}

#[test]
fn launch_context_rejects_generation_mismatch() {
    assert!(
        DaemonTelemetryLaunchContext::from_retained_fields(
            AUTHORITY,
            1,
            GENERATION,
            FENCE,
            PROFILE,
            GENERATION + 1,
        )
        .is_err()
    );
}

#[test]
fn service_maps_partial_and_unavailable_durable_data() {
    let (directory, store) = store();
    rusqlite::Connection::open(directory.path().join("telemetry.sqlite"))
        .unwrap()
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE provider_runtime_authority_state SET token_budget_limit = -1 WHERE id = 1;",
        )
        .unwrap();
    let (registry, _) = RecoveryObservationRegistry::new();
    let partial = make_service(
        Arc::clone(&store),
        Arc::new(registry),
        FixedClock(Timestamp::from_unix_micros(3_000_000)),
    )
    .query_operational_telemetry()
    .unwrap();
    assert!(matches!(
        partial.durable().meta().completeness(),
        TelemetryCompletenessV1::Partial
    ));

    rusqlite::Connection::open(directory.path().join("telemetry.sqlite"))
        .unwrap()
        .execute(
            "UPDATE provider_runtime_authority_state SET active = 0 WHERE id = 1",
            [],
        )
        .unwrap();
    let (registry, _) = RecoveryObservationRegistry::new();
    let unavailable = make_service(
        store,
        Arc::new(registry),
        FixedClock(Timestamp::from_unix_micros(3_000_000)),
    );
    assert!(matches!(
        unavailable.query_operational_telemetry(),
        Err(OperationalTelemetryQueryErrorV1::Unavailable)
    ));
}

#[test]
fn service_reads_a_fresh_clock_value_for_each_query() {
    let (_directory, store) = store();
    let (registry, _) = RecoveryObservationRegistry::new();
    let service = make_service(
        store,
        Arc::new(registry),
        SequenceClock(Mutex::new(VecDeque::from([
            Timestamp::from_unix_micros(1_000_000),
            Timestamp::from_unix_micros(2_000_000),
        ]))),
    );

    assert_eq!(
        service
            .query_operational_telemetry()
            .unwrap()
            .observed_at_unix_seconds(),
        1
    );
    assert_eq!(
        service
            .query_operational_telemetry()
            .unwrap()
            .observed_at_unix_seconds(),
        2
    );
}
