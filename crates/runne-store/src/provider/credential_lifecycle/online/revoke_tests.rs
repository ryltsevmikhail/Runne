use runne_provider::{
    BindCredentialReadback, ClaimCredentialOperation, CompleteCredentialOperation, CredentialFence,
    CredentialLifecycleRevision, CredentialNativeEffectDisposition, CredentialReadbackDisposition,
    CredentialReadinessDisposition, CredentialReadinessObservation, CredentialReadinessRevision,
    CredentialVersionRef, CredentialVersionState, ObserveNativeEffect,
    ProviderCredentialEnrollmentStore,
};

use super::online_claim_test_support::seal_claim;
use super::online_test_support::{
    complete_pair, digest, issue_ticket, operation, provider, qualified_release, revoke, store,
    ticket,
};

#[test]
fn credential_online_revoke_rejects_nonactive_target_without_fencing() {
    let store = store();
    complete_pair(&store, 10, "paired-exact-target");
    let before =
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    let template = revoke(20, "wrong-target", 2, 2);
    let input = runne_provider::BeginCredentialOperation::new(
        template.command_id(),
        template.idempotency_key().clone(),
        template.operation_id(),
        template.installation_owner_id(),
        provider(),
        runne_provider::CredentialOperationAction::Revoke,
        None,
        Some(CredentialVersionRef::new(provider(), 2).unwrap()),
        template.expected_lifecycle_revision(),
        template.expected_prior_fence(),
        template.begin_proof_digest(),
        template.begin_proof_expires_at_high_water(),
    )
    .unwrap()
    .with_qualified_release_tuple(qualified_release(92));
    assert!(matches!(
        ProviderCredentialEnrollmentStore::begin(&store, input),
        Err(runne_provider::CredentialLifecycleError::Conflict)
    ));
    let after = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    assert_eq!(after.active_version(), before.active_version());
    assert_eq!(after.fence(), before.fence());
    assert_eq!(after.lifecycle_revision(), before.lifecycle_revision());
    assert!(
        ProviderCredentialEnrollmentStore::find_by_begin_proof(
            &store,
            template.begin_proof_digest(),
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn credential_online_revoke_fence_survives_reopen_before_native_deletion() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("revoke-restart.sqlite");
    let store = super::online_claim_test_support::open_test_store(&path, 100);
    complete_pair(&store, 10, "paired-before-restart");
    let before =
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    ProviderCredentialEnrollmentStore::begin(&store, revoke(20, "revoke-restart", 2, 2)).unwrap();
    drop(store);

    let reopened = super::online_claim_test_support::open_test_store(&path, 101);
    let after =
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&reopened, &provider()).unwrap();
    assert!(before.active_version().is_some());
    assert!(after.active_version().is_none());
    assert!(after.fence() > before.fence());
    let pending =
        ProviderCredentialEnrollmentStore::load_operation(&reopened, operation(20)).unwrap();
    assert_eq!(
        pending.state(),
        runne_provider::CredentialOperationState::Prepared
    );
    assert_eq!(pending.target_credential_version(), before.active_version());
}

#[test]
fn credential_online_revoke_completes_after_committed_fence_readback_and_missing_readiness() {
    let store = store();
    complete_pair(&store, 10, "paired");
    let revoke_id = operation(20);
    ProviderCredentialEnrollmentStore::begin(&store, revoke(20, "revoke", 2, 2)).unwrap();
    let receipt = issue_ticket(&store, ticket(20, 1, 22, 23)).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(
            &store,
            ClaimCredentialOperation::new(receipt, digest(22), digest(23), digest(24), 1, 1)
                .unwrap(),
        ),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(revoke_id, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    let readback = BindCredentialReadback::new(
        revoke_id,
        CredentialReadbackDisposition::ExactAbsence,
        digest(25),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(&store, readback).unwrap();
    let readiness = CredentialReadinessObservation::new(
        operation(26),
        Some(revoke_id),
        provider(),
        CredentialLifecycleRevision::new(3).unwrap(),
        CredentialReadinessRevision::new(3).unwrap(),
        CredentialReadinessDisposition::Missing,
        None,
        qualified_release(92).digest(),
        100,
    )
    .unwrap();

    let lifecycle = ProviderCredentialEnrollmentStore::complete(
        &store,
        CompleteCredentialOperation::new(
            revoke_id,
            BindCredentialReadback::new(
                revoke_id,
                CredentialReadbackDisposition::ExactAbsence,
                digest(25),
            )
            .unwrap(),
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialFence::new(2).unwrap(),
        )
        .unwrap()
        .with_readiness_observation(readiness),
    )
    .unwrap();

    assert!(lifecycle.active_version().is_none());
    assert_eq!(lifecycle.lifecycle_revision().get(), 3);
    assert_eq!(lifecycle.fence().get(), 3);
    assert_eq!(
        ProviderCredentialEnrollmentStore::load_operation(&store, revoke_id)
            .unwrap()
            .state(),
        runne_provider::CredentialOperationState::Completed
    );
    let mirror: (String, Vec<u8>) = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT lifecycle_state, tombstone_digest
             FROM provider_credential_versions
             WHERE provider_id='openai' AND credential_version=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(mirror.0, "DELETED");
    assert_ne!(mirror.1, digest(25).as_bytes());
    let reference = CredentialVersionRef::new(provider(), 1).unwrap();
    assert_eq!(
        store.version_state(&reference).unwrap(),
        CredentialVersionState::Deleted
    );
    assert_eq!(
        store.tombstone_digest(&reference).unwrap(),
        Some(mirror.1.try_into().unwrap())
    );
}
