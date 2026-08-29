use super::*;
use runne_application::ports::RuntimeAuthorityId;
use runne_security::SecretBroker;
use std::sync::Arc;
use tempfile::TempDir;

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
