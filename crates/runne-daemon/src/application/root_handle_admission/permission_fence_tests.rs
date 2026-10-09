use super::*;
use std::os::unix::fs::DirBuilderExt;

fn admission() -> Arc<runne_platform::local_command_linux::LinuxCompositeScopeAdmission> {
    let directory = tempfile::tempdir().expect("temporary protected root");
    let root = std::fs::File::open(directory.path()).expect("open protected root");
    Arc::new(
        runne_platform::local_command_linux::LinuxCompositeScopeAdmission::new(&[&root])
            .expect("admission registry"),
    )
}

fn managed_connections(
    directory: &tempfile::TempDir,
) -> (
    String,
    runne_store::schema::ManagedConnection,
    runne_store::schema::ManagedConnection,
) {
    let daemon_dir = directory.path().join("runne-daemon");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&daemon_dir)
        .expect("private runtime directory");
    let path = daemon_dir.join("runtime.db");
    let writer = runne_store::schema::open_managed_connection(
        &path,
        runne_store::schema::ConnectionMode::Writer,
    )
    .expect("managed writer");
    runne_store::schema::apply_migrations(&writer).expect("runtime schema");
    let reader = runne_store::schema::open_managed_connection(
        &path,
        runne_store::schema::ConnectionMode::Reader,
    )
    .expect("managed reader");
    (path.to_string_lossy().into_owned(), writer, reader)
}

fn content_guard() -> Arc<dyn runne_application::prohibited_content::ProhibitedContentPort> {
    Arc::new(runne_security::SecretBroker::new().prohibited_content_guard())
}

#[test]
fn attempted_native_owner_failure_returns_before_bundle_publication() {
    let admitted = admission();
    let called = std::cell::Cell::new(false);
    let result = PermissionStartupBundle::with_native_owner_factory(
        Some(Arc::clone(&admitted)),
        |received| {
            called.set(true);
            assert!(Arc::ptr_eq(&admitted, &received));
            Err(PermissionStartupError::NativeOwnerUnavailable)
        },
    );

    assert!(called.get());
    assert_eq!(
        result.err(),
        Some(PermissionStartupError::NativeOwnerUnavailable)
    );
}

#[test]
fn successful_startup_publishes_admission_and_native_owner_together() {
    let bundle = PermissionStartupBundle::new(Some(admission())).expect("paired startup bundle");

    assert!(bundle.admission.is_some());
    assert!(bundle.native_owner.is_some());
}

#[test]
fn unavailable_startup_is_ownerless_and_mismatched_pair_never_falls_back() {
    let bundle = PermissionStartupBundle::new(None).expect("explicitly unavailable startup");

    assert!(bundle.admission.is_none());
    assert!(bundle.native_owner.is_none());
    assert_eq!(validate_store_owner_pair(false, false, true), Ok(false));
    assert!(validate_store_owner_pair(true, true, false).is_err());
    assert!(validate_store_owner_pair(true, false, false).is_err());
}

#[test]
fn configured_root_open_failure_aborts_prepare() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temporary startup directory");
    let broken_root = directory.path().join("broken-root");
    symlink(directory.path().join("missing-root"), &broken_root).expect("broken root link");
    let result = PermissionStartupBundle::prepare(
        &broken_root.join("runtime.db"),
        std::path::Path::new("/runtime.key"),
    );

    assert!(matches!(
        result,
        Err(crate::error::DaemonError::Bootstrap(_))
    ));
}

#[test]
fn no_configured_protected_roots_produces_paired_unavailable_startup() {
    let bundle = PermissionStartupBundle::prepare(
        std::path::Path::new("/runtime.db"),
        std::path::Path::new("/runtime.key"),
    )
    .expect("explicitly unavailable startup");

    assert!(bundle.permission_admission().is_none());
    assert!(bundle.native_owner.is_none());
}

#[test]
fn open_store_rejects_admission_without_t1_before_ownerless_open() {
    let directory = tempfile::tempdir().expect("temporary store");
    let (path, writer, reader) = managed_connections(&directory);
    let bundle = PermissionStartupBundle::new(Some(admission())).expect("paired owner");

    let opened = bundle.open_store(
        &path,
        writer,
        reader,
        runne_application::ports::RuntimeAuthorityId("runtime".into()),
        content_guard(),
        None,
    );

    assert_eq!(opened.err(), Some(unavailable_store_owner()));
}

#[test]
fn paired_store_open_failure_is_not_retried_ownerless() {
    let directory = tempfile::tempdir().expect("temporary store");
    let (path, writer, reader) = managed_connections(&directory);
    let trust = Arc::new(
        runne_store::ProjectTrustStore::open(std::path::Path::new(&path), [0x55; 16])
            .expect("trust sidecar"),
    );
    let bundle = PermissionStartupBundle::new(Some(admission())).expect("paired owner");

    let opened = bundle.open_store(
        &path,
        writer,
        reader,
        runne_application::ports::RuntimeAuthorityId("wrong-authority".into()),
        content_guard(),
        Some(trust),
    );

    assert!(matches!(
        opened,
        Err(runne_application::ports::CommitError::StorageFailure(
            runne_application::ports::StorageFailureKind::IntegrityViolation
        ))
    ));
}
