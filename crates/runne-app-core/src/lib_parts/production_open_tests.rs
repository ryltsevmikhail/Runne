use std::sync::Arc;

use runne_secure_store::test_support::DeterministicSecureStore;
use sha2::{Digest, Sha256};

fn expected_desktop_profile_digest() -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gocode/app-core/desktop-security-profile/v1\0");
    digest.update(("runne-desktop-profile/v1".len() as u64).to_be_bytes());
    digest.update(b"runne-desktop-profile/v1");
    digest.finalize().into()
}

/// Deterministic fail-closed coverage: a secure store whose every operation
/// is unavailable (all trait defaults) must deny production open before any
/// database file exists. Unlike the native-keyring probe below, this never
/// depends on whether the host secret service happens to be writable.
/// Only its non-macOS test constructs it; on macOS the production open path
/// itself is fail-closed without native keychain support.
#[cfg(not(target_os = "macos"))]
struct UnavailableSecureStore;

#[cfg(not(target_os = "macos"))]
impl runne_secure_store::SecureStore for UnavailableSecureStore {}

#[cfg(not(target_os = "macos"))]
#[test]
fn unavailable_secure_store_denies_production_open_before_database_creation() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");

    assert!(matches!(
        AppCore::open_production_with_secure(
            &path,
            RuntimeMode::ExternalLocal,
            Arc::new(UnavailableSecureStore)
        ),
        Err(AppCoreError::MutationUnavailable)
    ));
    assert!(!path.exists());
}

/// Production-backend invariant over the real native secure store: a failed
/// `open_production` must never leave a database file behind. On hosts with a
/// writable native secret service the open legitimately succeeds; the older
/// "always fails" assumption was host-state dependent (it flipped whenever the
/// desktop keyring collection was unlocked — the root cause of the bigpc CI
/// flake observed 2026-09-19).
#[cfg(not(target_os = "macos"))]
#[test]
fn production_open_failure_never_leaves_a_database_behind() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");

    match AppCore::open_production(&path, RuntimeMode::ExternalLocal) {
        // Writable native secret service on this host: the open succeeds.
        Ok(_) => {}
        Err(AppCoreError::MutationUnavailable) => {
            assert!(
                !path.exists(),
                "failed production open must not create the database"
            );
        }
        Err(other) => panic!("production open must fail closed, got {other:?}"),
    }
}

#[tokio::test]
async fn injected_production_open_is_anchored_and_configures_each_runtime_mode() {
    let directory = tempfile::tempdir().expect("directory");
    let digest = expected_desktop_profile_digest();
    let external_path = directory.path().join("external.sqlite3");
    let external = AppCore::open_production_with_secure(
        &external_path,
        RuntimeMode::ExternalLocal,
        Arc::new(DeterministicSecureStore::new(digest)),
    )
    .expect("open external core");
    let bundled_path = directory.path().join("bundled.sqlite3");
    let bundled = AppCore::open_production_with_secure(
        &bundled_path,
        RuntimeMode::Bundled,
        Arc::new(DeterministicSecureStore::new(digest)),
    )
    .expect("open bundled core");

    assert_eq!(external.runtime_mode(), RuntimeMode::ExternalLocal);
    assert_eq!(
        external.runtime_profile_path,
        Some(runne_runtime_client::default_local_profile_path().expect("profile path"))
    );
    assert!(external.mutation_security.is_some());
    assert_eq!(bundled.runtime_mode(), RuntimeMode::Bundled);
    assert_eq!(bundled.runtime_profile_path, None);
    assert!(bundled.mutation_security.is_some());
    for path in [&external_path, &bundled_path] {
        let connection = rusqlite::Connection::open(path).expect("open anchored database");
        let version: i64 = connection
            .query_row("SELECT schema_version FROM meta WHERE singleton=1", [], |row| row.get(0))
            .expect("schema version");
        assert_eq!(version, 8);
    }
}
