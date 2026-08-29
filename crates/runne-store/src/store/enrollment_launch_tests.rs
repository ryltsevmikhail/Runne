use super::*;
use runne_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use runne_application::{
    local_session::{
        BootstrapReservationError, BootstrapReservationStore, ConsumeReservation,
        ConsumedReservation, LocalSessionError, LocalSessionService, PreallocateReservation,
        Reservation,
    },
    ports::RuntimeAuthorityId,
};
use runne_domain::{event::Sensitivity, id::EventLogLineageId};
use runne_security::SecretBroker;
use std::sync::Arc;
use tempfile::TempDir;

struct NoopBootstrapStore;

impl BootstrapReservationStore for NoopBootstrapStore {
    fn preallocate(
        &self,
        _: PreallocateReservation,
    ) -> Result<Reservation, BootstrapReservationError> {
        Err(BootstrapReservationError::Storage)
    }

    fn consume_final(
        &self,
        _: ConsumeReservation<'_>,
    ) -> Result<ConsumedReservation, BootstrapReservationError> {
        Err(BootstrapReservationError::Storage)
    }

    fn observe_clock(&self, _: i64) -> Result<i64, BootstrapReservationError> {
        Err(BootstrapReservationError::Storage)
    }
}

fn binding(generation: u64, session_id: [u8; 16]) -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 31],
            ApiPrincipalId::new("store-enrollment").unwrap(),
            "018f2e3a-7000-7000-8000-000000000032"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "profile",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 33]),
        generation,
        session_id,
        7,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap()
}

fn store() -> (TempDir, StoreTransaction) {
    let directory = TempDir::new().expect("temporary root");
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).expect("daemon directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("root permissions");
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700))
            .expect("daemon permissions");
    }
    let database = daemon.join("event-log.sqlite");
    let store = StoreTransaction::open(
        &database.to_string_lossy(),
        RuntimeAuthorityId("enrollment-launch-test".into()),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .expect("store");
    (directory, store)
}

#[test]
fn enrollment_launch_generation_reservation_is_consecutive_and_current_only() {
    let (_directory, store) = store();
    let first = store
        .reserve_enrollment_launch_generation()
        .expect("first generation");
    let second = store
        .reserve_enrollment_launch_generation()
        .expect("second generation");

    assert_eq!((first, second), (1, 2));
    assert_eq!(store.validate_enrollment_launch_generation(second), Ok(()));
    for invalid in [0, first, second + 1] {
        assert_eq!(
            store.validate_enrollment_launch_generation(invalid),
            Err(EnrollmentLaunchGenerationError::CorruptData)
        );
    }
}

#[test]
fn enrollment_launch_generation_corruption_is_preserved() {
    let (_directory, store) = store();
    store
        .inner
        .writer
        .lock()
        .expect("writer")
        .execute(
            "INSERT INTO _daemon_info (key, value) VALUES ('launch_generation', '00')",
            [],
        )
        .expect("corrupt generation");

    assert_eq!(
        store.reserve_enrollment_launch_generation(),
        Err(EnrollmentLaunchGenerationError::CorruptData)
    );
    assert_eq!(
        store.validate_enrollment_launch_generation(1),
        Err(EnrollmentLaunchGenerationError::CorruptData)
    );
    let stored: String = store
        .inner
        .writer
        .lock()
        .expect("writer")
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = 'launch_generation'",
            [],
            |row| row.get(0),
        )
        .expect("corrupt value remains");
    assert_eq!(stored, "00");
}

#[test]
fn enrollment_launch_generation_consumption_is_one_time_and_current_only() {
    let (directory, store) = store();
    assert_eq!(
        store.consume_enrollment_launch_generation(1),
        Err(EnrollmentLaunchGenerationError::CorruptData)
    );
    let first = store.reserve_enrollment_launch_generation().unwrap();
    let left = store.clone();
    let database = directory.path().join("runne-daemon/event-log.sqlite");
    let right_path = database.clone();
    let left = std::thread::spawn(move || left.consume_enrollment_launch_generation(first));
    let right = std::thread::spawn(move || {
        let connection = rusqlite::Connection::open(right_path).unwrap();
        crate::schema::consume_reserved_launch_generation(&connection, first).is_ok()
    });
    assert_eq!(
        usize::from(left.join().unwrap().is_ok()) + usize::from(right.join().unwrap()),
        1
    );
    assert_eq!(
        store.consume_enrollment_launch_generation(first),
        Err(EnrollmentLaunchGenerationError::CorruptData)
    );

    let second = store.reserve_enrollment_launch_generation().unwrap();
    assert_eq!(
        store.consume_enrollment_launch_generation(first),
        Err(EnrollmentLaunchGenerationError::CorruptData)
    );
    assert_eq!(
        store.consume_enrollment_launch_generation(second + 1),
        Err(EnrollmentLaunchGenerationError::CorruptData)
    );
    assert_eq!(store.consume_enrollment_launch_generation(second), Ok(()));

    store
        .inner
        .writer
        .lock()
        .unwrap()
        .execute(
            "UPDATE _daemon_info SET value = '00' WHERE key = 'enrollment_launch_generation_consumed_v1'",
            [],
        )
        .unwrap();
    let third = store.reserve_enrollment_launch_generation().unwrap();
    assert_eq!(
        store.consume_enrollment_launch_generation(third),
        Err(EnrollmentLaunchGenerationError::CorruptData)
    );
}

#[test]
fn local_session_rotation_consumes_real_store_reservation_once() {
    let (_directory, store) = store();
    assert_eq!(
        (
            store.reserve_enrollment_launch_generation().unwrap(),
            store.reserve_enrollment_launch_generation().unwrap(),
        ),
        (1, 2)
    );
    let current = binding(1, [5; 16]);
    let next = binding(2, [9; 16]);
    let mut service = LocalSessionService::new_protected_with_stores(
        current.clone(),
        [1; 16],
        [2; 32],
        [0x22; 32],
        Arc::new(NoopBootstrapStore),
        Arc::new(store.clone()),
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    service
        .rotate_protected_enrollment_generation(
            &current,
            next.clone(),
            [0x33; 32],
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(service.current_binding(), &next);
    assert_eq!(
        store.consume_enrollment_launch_generation(2),
        Err(EnrollmentLaunchGenerationError::CorruptData)
    );
}

#[test]
fn local_session_reserve_admits_only_the_exact_successor_and_rotate_consumes_it_once() {
    let (_directory, store) = store();
    assert_eq!(store.reserve_enrollment_launch_generation().unwrap(), 1);
    let current = binding(1, [5; 16]);
    let service = LocalSessionService::new_protected_with_stores(
        current.clone(),
        [1; 16],
        [2; 32],
        [0x22; 32],
        Arc::new(NoopBootstrapStore),
        Arc::new(store.clone()),
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(service.reserve_protected_enrollment_generation(), Ok(2));

    // A second reservation advances the canonical counter past the pending
    // exact-successor expectation; the stale reservation fails closed.
    assert_eq!(
        service.reserve_protected_enrollment_generation(),
        Err(LocalSessionError::Unauthorized)
    );
    assert_eq!(service.current_binding(), &current);

    // Re-anchor on the canonical counter value and complete the reserved flow.
    let reanchored = binding(3, [5; 16]);
    let mut reanchored_service = LocalSessionService::new_protected_with_stores(
        reanchored.clone(),
        [1; 16],
        [2; 32],
        [0x22; 32],
        Arc::new(NoopBootstrapStore),
        Arc::new(store.clone()),
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(
        reanchored_service.reserve_protected_enrollment_generation(),
        Ok(4)
    );
    assert_eq!(reanchored_service.current_binding(), &reanchored);
    reanchored_service
        .rotate_protected_enrollment_generation(
            &reanchored,
            binding(4, [9; 16]),
            [0x33; 32],
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(reanchored_service.current_binding(), &binding(4, [9; 16]));
    // The reservation was consumed exactly once: replay fails closed.
    assert_eq!(
        store.consume_enrollment_launch_generation(4),
        Err(EnrollmentLaunchGenerationError::CorruptData)
    );
}
