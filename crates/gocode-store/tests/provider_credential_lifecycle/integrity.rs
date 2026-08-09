use gocode_provider::{
    CredentialLifecycleError, CredentialVersionState, ProviderCredentialVersionStore,
};
use rusqlite::Connection;

use super::support::*;

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

#[test]
fn activation_rejects_expired_lease_and_provider_fence_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("activation-fence.sqlite");
    let store = store(&path);
    let expired = version(1);
    prepare(&store, expired.clone());
    assert_eq!(
        store.activate(lease(expired, OWNER_A, 1, 51)).unwrap_err(),
        CredentialLifecycleError::StaleLease
    );

    let first = version(2);
    prepare(&store, first.clone());
    store
        .activate(lease(first.clone(), OWNER_A, i64::MAX, 52))
        .unwrap();
    revoke(&store, first, 52);
    let replacement = version(3);
    prepare(&store, replacement.clone());
    assert_eq!(
        store
            .activate(lease(replacement.clone(), OWNER_B, i64::MAX, 52))
            .unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
    store
        .activate(lease(replacement, OWNER_B, i64::MAX, 53))
        .unwrap();
}

#[test]
fn reconcile_rejects_corrupt_stored_reference_digest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("corrupt-ref.sqlite");
    let reference = version(1);
    let lifecycle = store(&path);
    prepare(&lifecycle, reference.clone());
    lifecycle
        .activate(lease(reference.clone(), OWNER_A, i64::MAX, 61))
        .unwrap();
    revoke(&lifecycle, reference, 61);
    drop(lifecycle);

    let connection = Connection::open(&path).unwrap();
    let trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger'
             AND name='provider_credential_identity_immutable'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_credential_identity_immutable")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_credential_versions SET ref_digest=zeroblob(32)
             WHERE provider_id='openai' AND credential_version=1",
            [],
        )
        .unwrap();
    connection.execute_batch(&trigger).unwrap();
    drop(connection);

    assert_eq!(
        store(&path).reconcile(100).unwrap_err(),
        CredentialLifecycleError::CorruptState
    );
}

#[test]
fn deleted_tombstone_rejects_every_row_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("immutable-tombstone.sqlite");
    let reference = version(1);
    let (store, native) = store_with_native(&path);
    prepare(&store, reference.clone());
    store
        .activate(lease(reference.clone(), OWNER_A, i64::MAX, 71))
        .unwrap();
    revoke(&store, reference.clone(), 71);
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
    assert_eq!(
        store
            .revoke_and_fence(
                gocode_provider::RevokeCredentialVersion::new(reference.clone(), 72).unwrap(),
            )
            .unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
    drop(store);

    let connection = Connection::open(path).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE provider_credential_versions SET tombstone_digest=?1
                 WHERE provider_id='openai' AND credential_version=1",
                [[0xD1_u8; 32].as_slice()],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE provider_credential_versions SET revocation_fence=72
                 WHERE provider_id='openai' AND credential_version=1",
                [],
            )
            .is_err()
    );
}
