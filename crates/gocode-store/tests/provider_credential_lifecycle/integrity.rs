use gocode_provider::{
    CredentialLifecycleError, CredentialVersionState, ProviderCredentialVersionStore,
};
use gocode_store::provider::SqliteProviderCredentialLifecycleStore;
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
fn activation_rejects_durable_provider_clock_rollback_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("activation-clock-rollback.sqlite");
    let first = version(1);
    let initial = SqliteProviderCredentialLifecycleStore::open_at(&path, 200).unwrap();
    prepare(&initial, first.clone());
    initial
        .activate(lease(first.clone(), OWNER_A, 500, 81))
        .unwrap();
    revoke(&initial, first, 81);
    drop(initial);

    let connection = Connection::open(&path).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE provider_credential_clock_high_water SET observed_at=100
                 WHERE provider_id='openai'",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM provider_credential_clock_high_water
                 WHERE provider_id='openai'",
                [],
            )
            .is_err()
    );
    drop(connection);

    let replacement = version(2);
    let rolled_back = SqliteProviderCredentialLifecycleStore::open_at(&path, 100).unwrap();
    prepare(&rolled_back, replacement.clone());
    assert_eq!(
        rolled_back
            .activate(lease(replacement.clone(), OWNER_B, 500, 82))
            .unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
    assert_eq!(
        rolled_back.version_state(&replacement).unwrap(),
        CredentialVersionState::Prepared
    );
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
    let connection = Connection::open(&path).unwrap();
    let state: String = connection
        .query_row(
            "SELECT lifecycle_state FROM provider_credential_versions
             WHERE provider_id='openai' AND credential_version=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "RETIRED");
}

#[test]
fn reconcile_validates_existing_gc_batch_before_mutating_retired_rows() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mixed-corrupt-gc.sqlite");
    let lifecycle = store(&path);
    let corrupt = version(1);
    prepare(&lifecycle, corrupt.clone());
    lifecycle
        .activate(lease(corrupt.clone(), OWNER_A, i64::MAX, 91))
        .unwrap();
    revoke(&lifecycle, corrupt.clone(), 91);
    assert_eq!(
        lifecycle.reconcile(100).unwrap().native_deletions().len(),
        1
    );
    let valid = version(2);
    prepare(&lifecycle, valid.clone());
    lifecycle
        .activate(lease(valid.clone(), OWNER_B, i64::MAX, 92))
        .unwrap();
    revoke(&lifecycle, valid.clone(), 92);
    drop(lifecycle);

    corrupt_ref_digest(&path, 1);
    assert_eq!(
        store(&path).reconcile(100).unwrap_err(),
        CredentialLifecycleError::CorruptState
    );
    let connection = Connection::open(&path).unwrap();
    for (version, expected) in [(1, "GC_CLAIMED"), (2, "RETIRED")] {
        let state: String = connection
            .query_row(
                "SELECT lifecycle_state FROM provider_credential_versions
                 WHERE provider_id='openai' AND credential_version=?1",
                [version],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, expected);
    }
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
