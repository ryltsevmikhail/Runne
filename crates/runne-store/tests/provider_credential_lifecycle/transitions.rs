use std::{fs, sync::Arc};

use runne_provider::{
    CredentialLifecycleError, CredentialVersionState, ProviderCredentialVersionStore, ProviderId,
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

    assert!(
        store(&path)
            .reconcile(100)
            .unwrap()
            .native_deletions()
            .is_empty()
    );
    assert_eq!(native.configured_versions(), 1);
    assert_eq!(
        store(&path).version_state(&reference).unwrap(),
        CredentialVersionState::Prepared
    );
}

#[test]
fn deleted_version_can_never_reclaim_native_create_authority() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("deleted-create-authority.sqlite");
    let (store, native) = store_with_native(&path);
    let provider = ProviderId::new("openai").unwrap();
    let source = store.provision_source([0xD4; 16]).unwrap();
    let provision = store
        .begin_provision(&provider, [0xD5; 16], &source)
        .unwrap();
    let create = store.claim_native_create(&provision).unwrap();
    assert_eq!(create.version_ref(), provision.version_ref());
    let provision = store.mark_native_created(&provision).unwrap();
    store
        .activate(lease(
            provision.version_ref().clone(),
            OWNER_A,
            i64::MAX,
            93,
        ))
        .unwrap();
    revoke(&store, provision.version_ref().clone(), 93);
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
        native.authorize_create(&create).unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
    assert_eq!(
        store.pending_provision(&provider).unwrap_err(),
        CredentialLifecycleError::LifecycleClosed
    );
    assert_eq!(
        store.claim_native_create(&provision).unwrap_err(),
        CredentialLifecycleError::LifecycleClosed
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
fn provider_dispatch_authority_selects_only_exact_active_owner_and_fence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dispatch-authority.sqlite");
    let store = store(&path);
    let reference = version(1);
    prepare(&store, reference.clone());
    store
        .activate(lease(reference.clone(), OWNER_A, 500, 9))
        .unwrap();

    let binding = store
        .authorize_active(reference.provider(), OWNER_A, 9, 100)
        .unwrap();
    assert_eq!(binding.version_ref(), &reference);
    assert_eq!(binding.owner(), &OWNER_A);
    assert_eq!(binding.expires_at(), 500);
    assert_eq!(binding.fencing_token(), 9);
    assert_eq!(
        store
            .authorize_active(reference.provider(), OWNER_B, 9, 100)
            .unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
    assert_eq!(
        store
            .authorize_active(reference.provider(), OWNER_A, 8, 100)
            .unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
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

    let pending = store.reconcile(100).unwrap();
    assert_eq!(pending.native_deletions().len(), 1);
    assert_eq!(pending.native_deletions()[0].version_ref(), &reference);
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
    let (store, native) = store_with_native(&path);
    let native = Arc::new(native);
    let reference = version(1);
    prepare(&store, reference.clone());
    native.create(reference.clone(), b"fixture-credential-value");
    store
        .activate(lease(reference.clone(), OWNER_A, 500, 13))
        .unwrap();
    revoke(&store, reference.clone(), 13);

    let pending = store.reconcile(100).unwrap();
    assert_eq!(pending.native_deletions().len(), 1);
    assert_eq!(pending.native_deletions()[0].version_ref(), &reference);
    assert_eq!(store.tombstone_digest(&reference).unwrap(), None);
    let proof = native
        .delete(pending.into_native_deletions().pop().unwrap())
        .unwrap();
    assert_eq!(store.tombstone_digest(&reference).unwrap(), None);
    store.complete_native_delete(proof).unwrap();

    assert_eq!(
        store.version_state(&reference).unwrap(),
        CredentialVersionState::Deleted
    );
    assert!(store.tombstone_digest(&reference).unwrap().is_some());
}

#[test]
fn tombstone_rejects_deletion_proof_from_foreign_native_authority() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreign-proof.sqlite");
    let (store, _native) = store_with_native(&path);
    let reference = version(1);
    prepare(&store, reference.clone());
    store
        .activate(lease(reference.clone(), OWNER_A, 500, 15))
        .unwrap();
    revoke(&store, reference.clone(), 15);
    store.reconcile(100).unwrap();

    let (foreign_lifecycle, foreign_native) =
        runne_provider::CredentialAuthorityPair::new().split();
    let proof = foreign_native
        .prove_deletion(foreign_lifecycle.issue_gc(reference.clone()))
        .unwrap();
    assert_eq!(
        store.complete_native_delete(proof).unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
    assert_eq!(
        store.version_state(&reference).unwrap(),
        CredentialVersionState::GcClaimed
    );
}

#[test]
fn sqlite_rows_never_contain_fixture_secret_or_derived_digest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secret-free.sqlite");
    let reference = version(1);
    let secret = b"fixture-secret-native-only-39b8";
    let secret_digest = Sha256::digest(secret);
    let (store, native) = store_with_native(&path);
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
