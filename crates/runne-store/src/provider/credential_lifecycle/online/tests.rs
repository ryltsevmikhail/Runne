use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BeginCredentialOperation, CredentialFence, CredentialLifecycleRevision,
    CredentialNativeEffectDisposition, CredentialOperationAction, CredentialOperationState,
    CredentialVersionRef, HardFenceProvider, ObserveNativeEffect,
    ProviderCredentialEnrollmentStore,
};

use super::online_claim_test_support::{open_test_store, seal_claim};
use super::online_test_support::*;

#[test]
fn credential_online_begin_exactly_replays_the_durable_operation() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_test_store(&directory.path().join("online.sqlite"), 100);
    let input = begin(1, "pair", 2);

    let first = ProviderCredentialEnrollmentStore::begin(&store, input).unwrap();
    let replay = ProviderCredentialEnrollmentStore::begin(&store, begin(1, "pair", 2)).unwrap();

    assert_eq!(first.snapshot(), replay.snapshot());
    assert_eq!(first.snapshot().state(), CredentialOperationState::Prepared);
}

#[test]
fn credential_online_ticket_reissue_has_one_claim_winner() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(3, "ticket", 4)).unwrap();
    issue_ticket(&store, ticket(3, 1, 5, 6)).unwrap();
    issue_ticket(&store, ticket(3, 2, 7, 8)).unwrap();

    let accepted = seal_claim(&store, claim(&store, 3, 2, 7, 8, 9));
    let replay = seal_claim(&store, claim(&store, 3, 2, 7, 8, 9));
    let accepted = ProviderCredentialEnrollmentStore::claim(&store, accepted).unwrap();
    let replay = ProviderCredentialEnrollmentStore::claim(&store, replay);

    assert_eq!(accepted.state(), CredentialOperationState::Claimed);
    assert_eq!(
        replay.unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
}

#[test]
fn credential_online_claim_permanently_tombstones_ticket_attempt() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(6, "claim-tombstone", 7)).unwrap();
    issue_ticket(&store, ticket(6, 1, 8, 9)).unwrap();

    ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(&store, claim(&store, 6, 1, 8, 9, 10)),
    )
    .unwrap();

    assert_eq!(ticket_state(&store, 6, 1), "TOMBSTONED");
}

#[test]
fn credential_online_cancel_permanently_tombstones_issued_ticket() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(7, "cancel-tombstone", 8)).unwrap();
    issue_ticket(&store, ticket(7, 1, 9, 10)).unwrap();
    let close = runne_provider::ClosePreparedCredentialOperation::new(
        operation(7),
        CredentialOperationState::Cancelled,
    )
    .unwrap();

    ProviderCredentialEnrollmentStore::cancel_before_claim(&store, close).unwrap();

    assert_eq!(ticket_state(&store, 7, 1), "TOMBSTONED");
}

#[test]
fn credential_online_claim_rechecks_current_head_before_consuming_ticket() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(11, "claim-head-cas", 12)).unwrap();
    issue_ticket(&store, ticket(11, 1, 13, 14)).unwrap();
    ProviderCredentialEnrollmentStore::hard_fence_provider(
        &store,
        HardFenceProvider::new(
            provider(),
            CredentialFence::new(1).unwrap(),
            CredentialFence::new(2).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();

    let result = ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(&store, claim(&store, 11, 1, 13, 14, 15)),
    );

    assert_eq!(
        result.unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    assert_eq!(ticket_state(&store, 11, 1), "ISSUED");
    assert_eq!(
        ProviderCredentialEnrollmentStore::load_operation(&store, operation(11))
            .unwrap()
            .state(),
        CredentialOperationState::Prepared
    );
}

#[test]
fn forged_claim_does_not_hard_fence_provider() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(10, "forged", 11)).unwrap();
    issue_ticket(&store, ticket(10, 1, 12, 13)).unwrap();

    let result = ProviderCredentialEnrollmentStore::claim(&store, claim(&store, 10, 1, 14, 13, 15));

    assert_eq!(
        result.unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    assert!(ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).is_ok());
}

#[test]
fn crash_after_native_returns_same_recovery_operation() {
    let store = store();
    admit_claim(&store, 16, "crash");
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(
            operation(16),
            CredentialNativeEffectDisposition::PossibleEffect,
        ),
    )
    .unwrap();

    let work = ProviderCredentialEnrollmentStore::reconcile_online(&store, 100).unwrap();

    assert_eq!(work.len(), 1);
    assert_eq!(work[0].operation().operation_id(), operation(16));
}

#[test]
fn rotation_revoke_advances_fence_and_never_restores_active() {
    let store = store();
    complete_pair(&store, 20, "pair");
    let active =
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    ProviderCredentialEnrollmentStore::begin(
        &store,
        revoke(
            21,
            "revoke",
            active.lifecycle_revision().get(),
            active.fence().get(),
        ),
    )
    .unwrap();

    let revoked =
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();

    assert!(revoked.active_version().is_none());
    assert!(revoked.fence() > active.fence());
}

#[test]
fn credential_aba_tombstone_blocks_replaying_old_begin_proof() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(30, "aba", 31)).unwrap();
    let close = runne_provider::ClosePreparedCredentialOperation::new(
        operation(30),
        CredentialOperationState::Cancelled,
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::cancel_before_claim(&store, close).unwrap();
    let tombstone = runne_provider::TombstoneCredentialOperation::new(
        operation(30),
        CredentialOperationState::Cancelled,
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::tombstone(&store, tombstone).unwrap();

    let replay = ProviderCredentialEnrollmentStore::begin(&store, begin(30, "aba", 31)).unwrap();

    assert_eq!(
        replay.snapshot().state(),
        CredentialOperationState::Tombstoned
    );
}

#[test]
fn provider_invariant_hard_fence_is_restart_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fence.sqlite");
    let store = open_test_store(&path, 100);
    ProviderCredentialEnrollmentStore::begin(&store, begin(40, "fence", 41)).unwrap();
    ProviderCredentialEnrollmentStore::hard_fence_provider(
        &store,
        HardFenceProvider::new(
            provider(),
            CredentialFence::new(1).unwrap(),
            CredentialFence::new(2).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    drop(store);
    let restarted = open_test_store(&path, 100);

    assert_eq!(
        ProviderCredentialEnrollmentStore::begin(&restarted, begin(42, "closed", 43)).unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
}

#[test]
fn credential_online_migrate_legacy_is_deferred_without_head_mutation() {
    let store = store();
    let provider = provider();
    let input = BeginCredentialOperation::new(
        CommandId::from_bytes([61; 16]),
        IdempotencyKey::new("legacy-deferred").unwrap(),
        operation(60),
        runne_provider::CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        provider.clone(),
        CredentialOperationAction::MigrateLegacy,
        Some(CredentialVersionRef::new(provider.clone(), 1).unwrap()),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(62),
        200,
    )
    .unwrap()
    .with_qualified_release_tuple(qualified_release(92));

    assert_eq!(
        ProviderCredentialEnrollmentStore::begin(&store, input).unwrap_err(),
        runne_provider::CredentialLifecycleError::LifecycleClosed
    );
    assert_eq!(
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider).unwrap_err(),
        runne_provider::CredentialLifecycleError::NotFound
    );
}
