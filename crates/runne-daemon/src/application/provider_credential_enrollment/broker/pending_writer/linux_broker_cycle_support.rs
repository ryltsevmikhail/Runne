//! Inert metadata fixtures and authoritative absence/reopen checks.
use super::*;

pub(super) fn cycle_binary() -> std::path::PathBuf {
    let built = std::process::Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "-p",
            "runne-cli",
            "--example",
            "writer_cycle_fixture",
        ])
        .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .unwrap();
    assert!(built.status.success(), "writer example must build");
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/writer_cycle_fixture")
}

pub(super) fn measurements(
    fixture: &broker_support::Fixture,
    channel: &LinuxCredentialBrokerChannel,
) -> CredentialMeasurementSnapshot {
    let (start, image, handle) = channel.claim_process_facts().unwrap();
    let a = &fixture.measurements;
    CredentialMeasurementSnapshot::new(
        a.candidate_source_identity([10; 32]).unwrap(),
        a.release_manifest_digest([11; 32]).unwrap(),
        a.desktop_executable_identity([12; 32]).unwrap(),
        a.writer_executable_identity(image).unwrap(),
        a.reader_executable_identity(
            Sha256::digest(std::fs::read(std::env::current_exe().unwrap()).unwrap()).into(),
        )
        .unwrap(),
        a.contract_bundle_digest([15; 32]).unwrap(),
        a.daemon_authority_id([16; 32]).unwrap(),
        a.protected_session_id([17; 32]).unwrap(),
        a.desktop_supervisor_generation(8).unwrap(),
        a.writer_launch_id([18; 32]).unwrap(),
        a.writer_process_start_identity(start).unwrap(),
        a.writer_process_handle_identity(handle).unwrap(),
        a.broker_channel_binding([21; 32]).unwrap(),
        a.continuation_binding_digest(fixture.continuation.as_bytes())
            .unwrap(),
    )
    .unwrap()
}

pub(super) fn assert_daemon_absence_wins(
    fixture: broker_support::Fixture,
    writer: &std::path::Path,
) {
    use crate::application::provider_credential_enrollment::CredentialEnrollmentRecoveryGateway;
    let daemon = std::env::current_exe().unwrap();
    let access = runne_secure_store::ProviderCredentialAccessPolicy::new(writer, &daemon).unwrap();
    // Deliberately separate fake backend: writer success cannot prove presence
    // to the daemon. The normal reader must report this store's exact absence.
    let _source = runne_secure_store::install_test_source(Box::new(
        runne_secure_store::CountingFakeSource::unlocked(),
    ));
    let (_, readback, _, _) =
        runne_secure_store::NativeProviderCredentialReaders::new(access).into_parts();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    CredentialEnrollmentRecoveryGateway::new(&fixture.store, readback.as_ref())
        .reconcile_online(now)
        .expect("daemon absence reconciliation");
    assert_eq!(
        fixture
            .store
            .load_operation(fixture.operation.operation_id())
            .unwrap()
            .state(),
        CredentialOperationState::Failed
    );
    assert!(
        fixture
            .store
            .lifecycle_snapshot(fixture.operation.provider())
            .unwrap()
            .active_version()
            .is_none()
    );
    let path = crate::application::provider_credential_enrollment::tests::nested_db(
        fixture._directory.path(),
        "broker.sqlite",
    );
    // Release the managed writer lease before opening a new daemon store.
    let operation_id = fixture.operation.operation_id();
    let provider = fixture.operation.provider().clone();
    drop(fixture.store);
    let reopened = runne_store::provider::SqliteProviderCredentialLifecycleStore::open(&path)
        .expect("reopen after releasing the prior writer");
    assert_eq!(
        reopened.load_operation(operation_id).unwrap().state(),
        CredentialOperationState::Failed
    );
    assert!(
        reopened
            .lifecycle_snapshot(&provider)
            .unwrap()
            .active_version()
            .is_none()
    );
}
