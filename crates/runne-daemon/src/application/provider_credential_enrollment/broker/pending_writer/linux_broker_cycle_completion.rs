//! Completion is driven by a separate daemon reader over a shared fake backend.
use super::*;
use crate::application::provider_credential_enrollment::CredentialEnrollmentRecoveryGateway;

pub(super) fn assert_daemon_presence_completes(
    fixture: broker_support::Fixture,
    writer: &std::path::Path,
) {
    let root = fixture._directory.path().join("fixture-store");
    let _source = runne_secure_store::install_test_source(Box::new(
        runne_secure_store::DirectoryFakeSource::new(&root).unwrap(),
    ));
    let access = runne_secure_store::ProviderCredentialAccessPolicy::new(
        writer,
        &std::env::current_exe().unwrap(),
    )
    .unwrap();
    let (_, readback, _, _) =
        runne_secure_store::NativeProviderCredentialReaders::new(access).into_parts();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let gateway = CredentialEnrollmentRecoveryGateway::new(&fixture.store, readback.as_ref());
    gateway
        .reconcile_online(now)
        .expect("independent daemon metadata readback and lifecycle CAS");
    let operation = fixture
        .store
        .load_operation(fixture.operation.operation_id())
        .unwrap();
    assert_eq!(operation.state(), CredentialOperationState::Completed);
    assert!(operation.metadata().readback_observation_digest().is_some());
    let lifecycle = fixture
        .store
        .lifecycle_snapshot(operation.provider())
        .unwrap();
    assert_eq!(
        lifecycle.active_version(),
        operation.allocated_credential_version()
    );
    assert!(lifecycle.active_version().is_some());
    // Reconciliation cannot create another version or repeat the activation CAS.
    gateway.reconcile_online(now).unwrap();
    let repeated = fixture
        .store
        .lifecycle_snapshot(operation.provider())
        .unwrap();
    assert_eq!(repeated.active_version(), lifecycle.active_version());
    assert_eq!(
        repeated.lifecycle_revision(),
        lifecycle.lifecycle_revision()
    );
    assert_eq!(
        repeated.next_credential_version(),
        lifecycle.next_credential_version()
    );
    let path = crate::application::provider_credential_enrollment::tests::nested_db(
        fixture._directory.path(),
        "broker.sqlite",
    );
    drop(gateway);
    drop(fixture.store);
    let reopened =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open(&path).unwrap();
    let persisted = reopened.load_operation(operation.operation_id()).unwrap();
    assert_eq!(persisted.state(), CredentialOperationState::Completed);
    assert_eq!(
        persisted.metadata().readback_observation_digest(),
        operation.metadata().readback_observation_digest()
    );
    let reopened_lifecycle = reopened.lifecycle_snapshot(operation.provider()).unwrap();
    assert_eq!(
        reopened_lifecycle.active_version(),
        lifecycle.active_version()
    );
    assert_eq!(
        reopened_lifecycle.lifecycle_revision(),
        lifecycle.lifecycle_revision()
    );
}
