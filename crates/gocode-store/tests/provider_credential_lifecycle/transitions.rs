use std::{fs, sync::Arc};

use gocode_provider::{
    CredentialLifecycleError, CredentialVersionState, ProviderCredentialVersionStore,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use super::support::*;

#[test]
fn prepared_native_create_is_idempotent_after_crash() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("prepared.sqlite");
    let reference = version(1);
    let native = FixtureNative::default();

    prepare(&store(&path), reference.clone());
    native.create(reference.clone(), b"fixture-credential-value");

    prepare(&store(&path), reference.clone());
    native.create(reference.clone(), b"fixture-credential-value");

    assert_eq!(native.configured_versions(), 1);
    assert_eq!(
        store(&path).version_state(&reference).unwrap(),
        CredentialVersionState::Prepared
    );
}

#[test]
fn revocation_fence_precedes_provider_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("revocation.sqlite");
    let store = store(&path);
    let reference = version(1);
    let lease = lease(reference.clone(), OWNER_A, 500, 7);
    prepare(&store, reference.clone());
    store.activate(lease.clone()).unwrap();
    let binding = store.authorize_dispatch(&lease, 100).unwrap();

    revoke(&store, reference, 7);

    assert_eq!(
        store.validate_dispatch(&binding, 100).unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
    assert_eq!(store.revocation_fence(binding.version_ref()).unwrap(), 7);
}

#[test]
fn gc_claim_blocks_new_leases() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("gc-claim.sqlite");
    let store = store(&path);
    let reference = version(1);
    let active = lease(reference.clone(), OWNER_A, 500, 11);
    prepare(&store, reference.clone());
    store.activate(active).unwrap();
    revoke(&store, reference.clone(), 11);

    assert_eq!(
        store.reconcile(100).unwrap().native_deletions(),
        std::slice::from_ref(&reference)
    );
    assert_eq!(
        store.version_state(&reference).unwrap(),
        CredentialVersionState::GcClaimed
    );
    assert_eq!(
        store
            .activate(lease(reference, OWNER_B, 900, 12))
            .unwrap_err(),
        CredentialLifecycleError::LifecycleClosed
    );
}

#[test]
fn native_delete_precedes_deleted_tombstone() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("delete-order.sqlite");
    let store = store(&path);
    let native = Arc::new(FixtureNative::default());
    let reference = version(1);
    prepare(&store, reference.clone());
    native.create(reference.clone(), b"fixture-credential-value");
    store
        .activate(lease(reference.clone(), OWNER_A, 500, 13))
        .unwrap();
    revoke(&store, reference.clone(), 13);

    let pending = store.reconcile(100).unwrap();
    assert_eq!(pending.native_deletions(), std::slice::from_ref(&reference));
    assert_eq!(store.tombstone_digest(&reference).unwrap(), None);
    native.delete(reference.clone());
    assert_eq!(store.tombstone_digest(&reference).unwrap(), None);
    store.complete_native_delete(reference.clone()).unwrap();

    assert_eq!(
        store.version_state(&reference).unwrap(),
        CredentialVersionState::Deleted
    );
    assert!(store.tombstone_digest(&reference).unwrap().is_some());
}

#[test]
fn sqlite_rows_never_contain_fixture_secret_or_derived_digest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secret-free.sqlite");
    let reference = version(1);
    let secret = b"fixture-secret-native-only-39b8";
    let secret_digest = Sha256::digest(secret);
    let native = FixtureNative::default();
    let store = store(&path);
    prepare(&store, reference.clone());
    native.create(reference.clone(), secret);
    store.activate(lease(reference, OWNER_A, 500, 17)).unwrap();
    drop(store);

    let bytes = fs::read(&path).unwrap();
    assert!(!bytes.windows(secret.len()).any(|window| window == secret));
    assert!(
        !bytes
            .windows(secret_digest.len())
            .any(|window| window == secret_digest.as_slice())
    );

    let connection = Connection::open(&path).unwrap();
    let columns: Vec<String> = connection
        .prepare("SELECT name FROM pragma_table_info('provider_credential_versions') ORDER BY cid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        columns,
        [
            "provider_id",
            "credential_version",
            "ref_digest",
            "lifecycle_state",
            "lease_owner",
            "lease_expires_at",
            "lease_fencing_token",
            "revocation_fence",
            "tombstone_digest",
        ]
    );
}

#[test]
fn sqlite_transition_checks_reject_unfenced_retirement_and_skips() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("transition-checks.sqlite");
    let store = store(&path);
    let active = version(1);
    let prepared = version(2);
    prepare(&store, active.clone());
    prepare(&store, prepared.clone());
    store
        .activate(lease(active.clone(), OWNER_A, 500, 41))
        .unwrap();

    let connection = Connection::open(&path).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE provider_credential_versions SET lifecycle_state='RETIRED'
             WHERE provider_id='openai' AND credential_version=1",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE provider_credential_versions SET revocation_fence=41
             WHERE provider_id='openai' AND credential_version=1",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE provider_credential_versions
             SET lifecycle_state='GC_CLAIMED', lease_owner=?1,
                 lease_expires_at=500, lease_fencing_token=42
             WHERE provider_id='openai' AND credential_version=2",
                [OWNER_B.as_slice()],
            )
            .is_err()
    );
    assert_eq!(
        store.version_state(&active).unwrap(),
        CredentialVersionState::Active
    );
    assert_eq!(
        store.version_state(&prepared).unwrap(),
        CredentialVersionState::Prepared
    );
}
