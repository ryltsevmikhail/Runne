use std::sync::{Arc, Barrier};

use runne_provider::{
    BeginCredentialOperation, BeginCredentialOperationOutcome, CredentialBindingDigest,
    CredentialFence, CredentialInstallationOwnerId, CredentialLifecycleError,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialVersionRef, ProviderCredentialEnrollmentStore, ProviderId,
};
use runne_domain::id::{CommandId, IdempotencyKey};

use super::online_claim_test_support::{open_test_store, reopen_test_store};
use super::online_test_support::{begin, begin_with_operation, complete_pair, revoke};

#[test]
fn credential_online_begin_first_commit_returns_fresh_winner() {
    let store = super::online_test_support::store();
    assert!(matches!(
        ProviderCredentialEnrollmentStore::begin(&store, begin(70, "fresh", 71)).unwrap(),
        BeginCredentialOperationOutcome::FreshWinner(_)
    ));
}

#[test]
fn credential_online_begin_restart_replay_returns_exact_replay() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replay.sqlite");
    let store = open_test_store(&path, 100);
    ProviderCredentialEnrollmentStore::begin(&store, begin(72, "replay", 73)).unwrap();
    drop(store);
    let restarted = open_test_store(&path, 100);
    let replay = ProviderCredentialEnrollmentStore::begin(
            &restarted,
            begin_with_operation(72, 74, "replay", 73, 200)
        )
        .unwrap();
    assert!(matches!(&replay, BeginCredentialOperationOutcome::ExactReplay(_)));
    assert_eq!(
        replay.snapshot().operation_id(),
        CredentialOperationId::from_bytes([72; 16]).unwrap()
    );
}

#[test]
fn credential_online_begin_two_connections_have_one_fresh_winner_and_one_exact_replay() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("concurrent.sqlite");
    let left = Arc::new(open_test_store(&path, 100));
    let right = Arc::new(reopen_test_store(&path, 100));
    let barrier = Arc::new(Barrier::new(2));
    let run = |store: Arc<super::SqliteProviderCredentialLifecycleStore>, operation| {
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            ProviderCredentialEnrollmentStore::begin(
                store.as_ref(),
                begin_with_operation(75, operation, "concurrent", 76, 200),
            )
            .unwrap()
        })
    };
    let left = run(left, 77);
    let right = run(right, 78);
    let left = left.join().unwrap();
    let right = right.join().unwrap();
    assert!(left.is_fresh_winner() ^ right.is_fresh_winner());
    assert_eq!(
        left.snapshot().operation_id(),
        right.snapshot().operation_id()
    );
}

#[test]
fn credential_online_begin_replay_requires_every_immutable_field() {
    let store = super::online_test_support::store();
    ProviderCredentialEnrollmentStore::begin(
        &store,
        replay_input((79, 80, "immutable", 42, "openai", 1, 1, 1, 81, 200)),
    )
    .unwrap();
    for input in [
        replay_input((82, 83, "immutable", 42, "openai", 1, 1, 1, 81, 200)),
        replay_input((79, 83, "different", 42, "openai", 1, 1, 1, 81, 200)),
        replay_input((79, 83, "immutable", 43, "openai", 1, 1, 1, 81, 200)),
        replay_input((79, 83, "immutable", 42, "anthropic", 1, 1, 1, 81, 200)),
        replay_input((79, 83, "immutable", 42, "openai", 2, 1, 1, 81, 200)),
        replay_input((79, 83, "immutable", 42, "openai", 1, 2, 1, 81, 200)),
        replay_input((79, 83, "immutable", 42, "openai", 1, 1, 2, 81, 200)),
        replay_input((79, 83, "immutable", 42, "openai", 1, 1, 1, 82, 200)),
        replay_input((79, 83, "immutable", 42, "openai", 1, 1, 1, 81, 201)),
    ] {
        assert_eq!(
            ProviderCredentialEnrollmentStore::begin(&store, input).unwrap_err(),
            CredentialLifecycleError::Conflict
        );
    }
}

type ReplayCase = (u8, u8, &'static str, u8, &'static str, u64, u64, u64, u8, u64);

fn replay_input(
    (command, operation, key, owner, provider, allocated, revision, fence, proof, expiry): ReplayCase,
) -> BeginCredentialOperation {
    let provider = ProviderId::new(provider).unwrap();
    BeginCredentialOperation::new(
        CommandId::from_bytes([command.wrapping_add(20); 16]),
        IdempotencyKey::new(key).unwrap(),
        CredentialOperationId::from_bytes([operation; 16]).unwrap(),
        CredentialInstallationOwnerId::from_bytes([owner; 32]).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(CredentialVersionRef::new(provider, allocated).unwrap()),
        None,
        CredentialLifecycleRevision::new(revision).unwrap(),
        CredentialFence::new(fence).unwrap(),
        CredentialBindingDigest::from_measured([proof; 32]).unwrap(),
        expiry,
    )
    .unwrap()
}

#[test]
fn credential_online_begin_replay_rejects_an_occupied_proposed_operation_alias() {
    let store = super::online_test_support::store();
    ProviderCredentialEnrollmentStore::begin(
        &store,
        begin_with_operation(94, 94, "replay-alias", 95, 200),
    )
    .unwrap();
    complete_pair(&store, 94, "replay-alias");
    ProviderCredentialEnrollmentStore::begin(&store, revoke(96, "occupied-alias", 2, 2)).unwrap();

    assert_eq!(
        ProviderCredentialEnrollmentStore::begin(
            &store,
            begin_with_operation(94, 96, "replay-alias", 95, 200),
        )
        .unwrap_err(),
        CredentialLifecycleError::Conflict
    );
}

#[test]
fn credential_online_begin_expired_fresh_proof_stays_closed_after_clock_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("expired.sqlite");
    let store = open_test_store(&path, 100);
    assert_eq!(
        ProviderCredentialEnrollmentStore::begin(
            &store,
            begin_with_operation(84, 85, "expired", 86, 100)
        )
        .unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
    drop(store);
    let rolled_back = open_test_store(&path, 50);
    assert_eq!(
        ProviderCredentialEnrollmentStore::begin(
            &rolled_back,
            begin_with_operation(84, 85, "expired", 86, 100)
        )
        .unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
    assert_eq!(operation_count(&rolled_back), 0);
}

#[test]
fn credential_online_begin_expired_exact_replay_is_projection_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("projection.sqlite");
    let store = open_test_store(&path, 100);
    ProviderCredentialEnrollmentStore::begin(
        &store,
        begin_with_operation(87, 88, "projection", 89, 200),
    )
    .unwrap();
    drop(store);
    let expired = open_test_store(&path, 200);
    assert!(matches!(
        ProviderCredentialEnrollmentStore::begin(
            &expired,
            begin_with_operation(87, 90, "projection", 89, 200)
        )
        .unwrap(),
        BeginCredentialOperationOutcome::ExactReplay(_)
    ));
}

#[test]
fn credential_online_revoke_begin_never_regresses_observed_high_water() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("revoke-clock.sqlite");
    let store = open_test_store(&path, 100);
    complete_pair(&store, 91, "paired");
    drop(store);
    let rolled_back = open_test_store(&path, 50);
    ProviderCredentialEnrollmentStore::begin(&rolled_back, revoke(92, "revoke", 2, 2)).unwrap();
    assert_eq!(observed_at_high_water(&rolled_back), 100);
}

fn operation_count(store: &super::SqliteProviderCredentialLifecycleStore) -> i64 {
    store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_operations",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn observed_at_high_water(store: &super::SqliteProviderCredentialLifecycleStore) -> i64 {
    store.connection.lock().unwrap().query_row("SELECT observed_at_high_water FROM provider_credential_authority_heads WHERE provider_id='openai'", [], |row| row.get(0)).unwrap()
}
