use runne_provider::{CredentialLifecycleError, ProviderCredentialVersionStore};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use super::support::*;

#[test]
fn diagnostics_reject_deleted_runne_tombstone_without_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("deleted-runne-tombstone.sqlite");
    let (store, native) = store_with_native(&path);
    let reference = version(1);
    prepare(&store, reference.clone());
    store
        .activate(lease(reference.clone(), OWNER_A, 500, 1))
        .unwrap();
    revoke(&store, reference.clone(), 1);
    let proof = native
        .delete(
            store
                .reconcile(100)
                .unwrap()
                .into_native_deletions()
                .pop()
                .unwrap(),
        )
        .unwrap();
    store.complete_native_delete(proof).unwrap();
    seed_tombstone(&path, &reference, runne_tombstone(&reference));
    let before = credential_snapshot(&path);

    assert_eq!(
        store.version_state(&reference),
        Err(CredentialLifecycleError::CorruptState)
    );
    assert_eq!(
        store.tombstone_digest(&reference),
        Err(CredentialLifecycleError::CorruptState)
    );
    assert_eq!(credential_snapshot(&path), before);
}

#[test]
fn diagnostics_reject_non_deleted_tombstone_without_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("prepared-runne-tombstone.sqlite");
    let store = store(&path);
    let reference = version(1);
    prepare(&store, reference.clone());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_credential_versions SET tombstone_digest = ?1
             WHERE provider_id = ?2 AND credential_version = ?3",
            rusqlite::params![
                runne_tombstone(&reference).as_slice(),
                reference.provider().as_str(),
                reference.version() as i64,
            ],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = OFF;")
        .unwrap();
    let before = credential_snapshot(&path);

    assert_eq!(
        store.version_state(&reference),
        Err(CredentialLifecycleError::CorruptState)
    );
    assert_eq!(
        store.tombstone_digest(&reference),
        Err(CredentialLifecycleError::CorruptState)
    );
    assert_eq!(credential_snapshot(&path), before);
}

fn runne_tombstone(reference: &runne_provider::CredentialVersionRef) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"RUNNE_CREDENTIAL_TOMBSTONE_V1\0");
    hasher.update(reference.ref_digest());
    hasher.finalize().into()
}

fn seed_tombstone(
    path: &std::path::Path,
    reference: &runne_provider::CredentialVersionRef,
    digest: [u8; 32],
) {
    let connection = Connection::open(path).unwrap();
    let trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger'
             AND name = 'provider_credential_identity_immutable'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_credential_identity_immutable")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_credential_versions SET tombstone_digest = ?1
             WHERE provider_id = ?2 AND credential_version = ?3",
            rusqlite::params![
                digest.as_slice(),
                reference.provider().as_str(),
                reference.version() as i64,
            ],
        )
        .unwrap();
    connection.execute_batch(&trigger).unwrap();
}

fn credential_snapshot(path: &std::path::Path) -> (String, Option<Vec<u8>>) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT lifecycle_state, tombstone_digest
             FROM provider_credential_versions
             WHERE provider_id = 'openai' AND credential_version = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}
