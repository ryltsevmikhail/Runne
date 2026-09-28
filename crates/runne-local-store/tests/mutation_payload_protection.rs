#![cfg(feature = "test-support")]

use runne_local_store::{LocalStore, MutationRecoveryBinding, MutationRecoveryLimit};
use runne_secure_store::{SecureStore, test_support::DeterministicSecureStore};

#[path = "support/mutation_payload_support.rs"]
mod support;
use support::*;

#[test]
fn prepared_and_reopened_command_is_ciphertext_in_database_wal_and_shm() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("desktop-profile.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let mut store = LocalStore::open_anchored(&path, &secure, PROFILE).unwrap();
    let permit = store
        .prepare_anchored_mutation_v7(&secure, identity("encrypted-input"), command())
        .unwrap();
    assert_eq!(permit.record().normalized_command(), Some(&command()));
    let stored: Vec<u8> = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT normalized_command FROM mutation_ledger",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(stored.starts_with(b"RNV9"));
    assert_no_input_in_sqlite_family(&path);
    drop(store);

    let mut reopened = LocalStore::open_anchored(&path, &secure, PROFILE).unwrap();
    let binding = MutationRecoveryBinding::new(RUNTIME, PRINCIPAL).unwrap();
    let evidence = reopened
        .recover_anchored_mutations_v7(&secure, binding, MutationRecoveryLimit::new(1).unwrap())
        .unwrap();
    assert_eq!(evidence.records().len(), 1);
    assert_eq!(evidence.records()[0].normalized_command(), &command());
    assert_no_input_in_sqlite_family(&path);
}

#[test]
fn unsupported_secure_store_fails_before_creating_or_upgrading_a_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("unsupported-profile.sqlite3");
    let secure = DeterministicSecureStore::without_mutation_payload_encryption(PROFILE);
    assert!(LocalStore::open_anchored(&path, &secure, PROFILE).is_err());
    assert!(!path.exists());
}

#[test]
fn unsupported_secure_store_leaves_an_existing_v8_profile_and_anchor_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("unsupported-existing.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let mut store = LocalStore::open_anchored(&path, &secure, PROFILE).unwrap();
    store
        .prepare_anchored_mutation_v7(&secure, identity("preserved-v8-input"), command())
        .unwrap();
    runne_local_store::security_open_test_support::downgrade_to_v8_for_test(
        &mut store, &secure, "",
    )
    .unwrap();
    drop(store);
    let original = sqlite_family_snapshot(&path);
    let lock = secure.acquire_security_profile_lock(PROFILE).unwrap();
    let original_anchor = secure.read_security_anchor(&lock).unwrap();
    drop(lock);
    secure.disable_mutation_payload_encryption();

    assert!(LocalStore::open_anchored(&path, &secure, PROFILE).is_err());
    assert_eq!(sqlite_family_snapshot(&path), original);
    let lock = secure.acquire_security_profile_lock(PROFILE).unwrap();
    assert_eq!(secure.read_security_anchor(&lock).unwrap(), original_anchor);
}
