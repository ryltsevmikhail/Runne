use std::sync::Arc;

use gocode_secure_store::test_support::DeterministicSecureStore;
use sha2::{Digest, Sha256};

fn expected_desktop_profile_digest() -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gocode/app-core/desktop-security-profile/v1\0");
    digest.update(("gocode-desktop-profile/v1".len() as u64).to_be_bytes());
    digest.update(b"gocode-desktop-profile/v1");
    digest.finalize().into()
}

#[cfg(not(target_os = "macos"))]
#[test]
fn production_open_fails_closed_before_creating_a_database_without_native_secure_store() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");

    assert!(matches!(
        AppCore::open_production(&path, RuntimeMode::ExternalLocal),
        Err(AppCoreError::MutationUnavailable)
    ));
    assert!(!path.exists());
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
        Some(gocode_runtime_client::default_local_profile_path().expect("profile path"))
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
