use super::PersistentDeterministicSecureStore;
use crate::{SecureStore, SecurityAnchorV1, StoredSecurityAnchor};

#[test]
fn anchor_survives_store_and_process_style_reopen_without_database_reconstruction() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [0x49; 32];
    let database = [0x58; 32];
    {
        let store = PersistentDeterministicSecureStore::open(directory.path(), profile).unwrap();
        let lock = store.acquire_security_profile_lock(profile).unwrap();
        let seal = store
            .seal_security_transaction(&lock, database, 1, [0x67; 32], [0; 32])
            .unwrap();
        let anchor =
            SecurityAnchorV1::new(profile, database, 1, [0x67; 32], [0; 32], seal).unwrap();
        store.initialize_security_anchor(&lock, &anchor).unwrap();
        assert_eq!(
            store.read_security_anchor(&lock).unwrap(),
            StoredSecurityAnchor::V1(anchor)
        );
    }
    let reopened = PersistentDeterministicSecureStore::open(directory.path(), profile).unwrap();
    let lock = reopened.acquire_security_profile_lock(profile).unwrap();
    let StoredSecurityAnchor::V1(anchor) = reopened.read_security_anchor(&lock).unwrap() else {
        panic!("the independently persisted fixture anchor must survive reopen");
    };
    reopened
        .verify_security_transaction(&lock, &anchor)
        .unwrap();
    assert_eq!(anchor.database_identity, database);
    assert_eq!(
        std::fs::metadata(directory.path().join("anchor.v1"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn reopening_with_another_profile_does_not_rebind_the_anchor() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [0x1A; 32];
    let anchor = seed_anchor(directory.path(), profile);
    let reopened = PersistentDeterministicSecureStore::open(directory.path(), [0x2B; 32]).unwrap();
    let lock = reopened.acquire_security_profile_lock([0x2B; 32]).unwrap();
    assert_eq!(
        reopened.read_security_anchor(&lock).unwrap(),
        StoredSecurityAnchor::V1(anchor.clone())
    );
    assert_eq!(
        reopened.verify_security_transaction(&lock, &anchor),
        Err(crate::SecureStoreError::InvalidSeal)
    );
}

#[test]
fn modified_anchor_bytes_fail_seal_verification_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [0x36; 32];
    let _anchor = seed_anchor(directory.path(), profile);
    let path = directory.path().join("anchor.v1");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[80] ^= 0x01;
    std::fs::write(path, bytes).unwrap();
    let reopened = PersistentDeterministicSecureStore::open(directory.path(), profile).unwrap();
    let lock = reopened.acquire_security_profile_lock(profile).unwrap();
    let StoredSecurityAnchor::V1(anchor) = reopened.read_security_anchor(&lock).unwrap() else {
        panic!("tampered but well-formed anchor bytes should be parsed before seal validation");
    };
    assert_eq!(
        reopened.verify_security_transaction(&lock, &anchor),
        Err(crate::SecureStoreError::InvalidSeal)
    );
}

fn seed_anchor(directory: &std::path::Path, profile: [u8; 32]) -> SecurityAnchorV1 {
    let store = PersistentDeterministicSecureStore::open(directory, profile).unwrap();
    let lock = store.acquire_security_profile_lock(profile).unwrap();
    let database = [0x58; 32];
    let seal = store
        .seal_security_transaction(&lock, database, 1, [0x67; 32], [0; 32])
        .unwrap();
    let anchor = SecurityAnchorV1::new(profile, database, 1, [0x67; 32], [0; 32], seal).unwrap();
    store.initialize_security_anchor(&lock, &anchor).unwrap();
    anchor
}

use std::os::unix::fs::PermissionsExt;
