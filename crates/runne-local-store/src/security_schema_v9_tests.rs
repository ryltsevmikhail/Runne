use crate::LocalStore;
use runne_secure_store::test_support::DeterministicSecureStore;

#[test]
fn v9_writer_profile_is_rejected_by_the_legacy_v8_schema_validator() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let profile = [223; 32];
    let secure = DeterministicSecureStore::new(profile);
    drop(LocalStore::open_anchored(&path, &secure, profile).unwrap());
    let connection = rusqlite::Connection::open(path).unwrap();
    assert!(crate::security_schema_v8::validate_v8_schema(&connection).is_err());
    crate::security_schema_v9::validate_v9_schema(&connection).unwrap();
}
