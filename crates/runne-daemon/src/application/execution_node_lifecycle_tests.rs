use super::*;
#[path = "execution_node_lifecycle_tests/reconciliation.rs"]
mod reconciliation;
#[path = "execution_node_lifecycle_tests/recovery_lease.rs"]
mod recovery_lease;
use runne_api::{
    ApiPrincipalId, DaemonInstanceId, EventLogLineageId, RuntimeSessionBinding,
    StableRuntimeBinding,
};
use runne_application::local_session::{
    BootstrapReservationError, BootstrapReservationStore, ConsumeReservation, ConsumedReservation,
    LocalSessionService, PreallocateReservation, Reservation,
};
use runne_application::ports::RuntimeAuthorityId;
use runne_domain::event::Sensitivity;
use runne_security::SecretBroker;
use runne_store::schema::{
    ConnectionMode, apply_migrations, ensure_authority_id, next_launch_generation,
    open_managed_connection,
};

struct NoBootstrapReservations;

impl BootstrapReservationStore for NoBootstrapReservations {
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

fn test_binding(
    authority: [u8; 16],
    daemon: [u8; 16],
    generation: u64,
    epoch: u64,
) -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            authority,
            ApiPrincipalId::new("lifecycle-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000013"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "profile",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes(daemon),
        generation,
        [generation as u8; 16],
        epoch,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap()
}

fn store_fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    StoreTransaction,
    [u8; 16],
    u64,
) {
    let directory = tempfile::tempdir().unwrap();
    let daemon_dir = directory.path().join("daemon");
    std::fs::create_dir(&daemon_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon_dir.join("store.sqlite");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let authority = *uuid::Uuid::now_v7().as_bytes();
    ensure_authority_id(&connection, &authority).unwrap();
    let generation = next_launch_generation(&connection).unwrap();
    drop(connection);
    let store = StoreTransaction::open(
        path.to_str().unwrap(),
        RuntimeAuthorityId("linux-lifecycle-test".into()),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    (directory, path, store, authority, generation)
}

fn node_generation_and_expiry(path: &std::path::Path, authority: [u8; 16]) -> (u64, i64) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row(
            "SELECT launch_generation,expires_at_ms FROM execution_nodes WHERE node_id=?1",
            [authority.as_slice()],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap()
}

fn protected_sessions(
    binding: RuntimeSessionBinding,
    store: StoreTransaction,
) -> Arc<Mutex<LocalSessionService>> {
    Arc::new(Mutex::new(
        LocalSessionService::new_protected_with_stores(
            binding,
            [7; 16],
            [8; 32],
            [9; 32],
            Arc::new(NoBootstrapReservations),
            Arc::new(store),
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap(),
    ))
}

#[test]
fn live_pending_successor_defers_stale_heartbeat_then_updates_only_after_rotation() {
    let (_directory, path, store, authority, generation) = store_fixture();
    let daemon = *uuid::Uuid::now_v7().as_bytes();
    let worker_epoch = Arc::new(std::sync::atomic::AtomicU64::new(generation));
    let mut node = LinuxExecutionNode::with_worker_epoch(
        authority,
        authority,
        daemon,
        generation,
        Arc::clone(&worker_epoch),
    );
    let sessions = protected_sessions(
        test_binding(authority, daemon, generation, 7),
        store.clone(),
    );
    node.register(&store, &sessions).unwrap();
    assert_eq!(
        worker_epoch.load(std::sync::atomic::Ordering::Acquire),
        generation
    );

    let reserved = sessions
        .lock()
        .unwrap()
        .reserve_protected_enrollment_generation()
        .unwrap();
    assert_eq!(reserved, generation + 1);
    let lease_before_pending = node_generation_and_expiry(&path, authority);
    node.reconcile(&store, &sessions).unwrap();
    assert_eq!(node.launch_generation, generation);
    assert_eq!(
        worker_epoch.load(std::sync::atomic::Ordering::Acquire),
        generation
    );
    assert_eq!(
        node_generation_and_expiry(&path, authority),
        lease_before_pending
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        runne_store::execution_node::eligible_local_linux_node(&connection).unwrap(),
        None
    );
    assert_eq!(
        store.validate_enrollment_launch_generation(reserved),
        Ok(())
    );

    let old_process = protected_sessions(
        test_binding(authority, daemon, generation, 7),
        store.clone(),
    );
    let mut stale_node = LinuxExecutionNode::new(authority, authority, daemon, generation);
    assert!(stale_node.reconcile(&store, &old_process).is_err());
    assert_eq!(stale_node.launch_generation, generation);

    let current = sessions.lock().unwrap().current_binding().clone();
    let successor = test_binding(authority, daemon, reserved, 8);
    sessions
        .lock()
        .unwrap()
        .rotate_protected_enrollment_epoch(
            &current,
            successor,
            [11; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .unwrap();
    node.reconcile(&store, &sessions).unwrap();
    assert_eq!(node.launch_generation, reserved);
    assert_eq!(
        worker_epoch.load(std::sync::atomic::Ordering::Acquire),
        reserved
    );
    assert_eq!(node_generation_and_expiry(&path, authority).0, reserved);

    let current = sessions.lock().unwrap().current_binding().clone();
    let renewed = RuntimeSessionBinding::new(
        current.stable().clone(),
        current.ephemeral().daemon_instance_id(),
        reserved,
        [19; 16],
        current.ephemeral().authorization_epoch(),
        current.ephemeral().sensitivity_ceiling(),
        *current.certificate_sha256(),
    )
    .unwrap();
    sessions
        .lock()
        .unwrap()
        .rotate_protected_bootstrap(
            renewed,
            [20; 32],
            Duration::from_secs(2),
            Duration::from_secs(30),
        )
        .unwrap();
    node.reconcile(&store, &sessions).unwrap();
    assert_eq!(node.launch_generation, reserved);

    let unrelated = store.reserve_enrollment_launch_generation().unwrap();
    assert_eq!(unrelated, reserved + 1);
    assert!(node.reconcile(&store, &sessions).is_err());
    assert_eq!(node.launch_generation, reserved);
}
