use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BeginCredentialOperation, BindCredentialReadback, ClaimCredentialOperation,
    CompleteCredentialOperation, CredentialBindingDigest, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialNativeEffectDisposition,
    CredentialOperationAction, CredentialReadbackDisposition, CredentialReadinessDisposition,
    CredentialReadinessObservation, CredentialReadinessRevision, CredentialVersionRef,
    ObserveNativeEffect, ProviderCredentialEnrollmentStore,
};

use super::online_claim_test_support::seal_claim;
use super::online_test_support::{
    complete_pair, digest, issue_ticket, operation, provider, qualified_release, store, ticket,
};

#[test]
fn retired_cleanup_completion_advances_authority_and_replays_exactly() {
    let store = store();
    let retired = CredentialVersionRef::new(provider(), 1).unwrap();
    let active = CredentialVersionRef::new(provider(), 2).unwrap();

    complete_pair(&store, 10, "first-pair");
    complete_version_two(&store, &active);
    prepare_retired_cleanup(&store, &retired);

    let first = ProviderCredentialEnrollmentStore::complete_with_receipt(&store, cleanup_completion())
        .unwrap();
    let head = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();

    assert_eq!(first.action(), CredentialOperationAction::RetiredVersionCleanup);
    assert_eq!(first.target(), Some(&retired));
    assert_eq!(first.successor(), head);
    assert_eq!(head.active_version(), Some(&active));
    assert_eq!(head.lifecycle_revision().get(), 4);
    assert_eq!(head.fence().get(), 4);
    assert_eq!(head.readiness_revision().get(), 4);
    assert_eq!(version_state(&store, 1), "DELETED");
    assert_eq!(version_state(&store, 2), "ACTIVE");
    assert_eq!(
        readiness(&store),
        (4, 4, active.ref_digest().to_vec(), operation(12).as_bytes().to_vec())
    );

    let replay = ProviderCredentialEnrollmentStore::complete_with_receipt(&store, cleanup_completion())
        .unwrap();
    assert_eq!(replay, first);
}

fn complete_version_two(
    store: &super::SqliteProviderCredentialLifecycleStore,
    active: &CredentialVersionRef,
) {
    let input = BeginCredentialOperation::new(
        CommandId::from_bytes([31; 16]),
        IdempotencyKey::new("second-pair").unwrap(),
        operation(11),
        CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        provider(),
        CredentialOperationAction::Pair,
        Some(active.clone()),
        None,
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialFence::new(2).unwrap(),
        digest(12),
        200,
    )
    .unwrap()
    .with_qualified_release_tuple(qualified_release(92));
    ProviderCredentialEnrollmentStore::begin(store, input).unwrap();
    let receipt = issue_ticket(store, ticket(11, 1, 13, 14)).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        store,
        seal_claim(store, ClaimCredentialOperation::new(receipt, digest(13), digest(14), digest(15), 1, 1).unwrap()),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        store,
        ObserveNativeEffect::new(operation(11), CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        store,
        BindCredentialReadback::new(operation(11), CredentialReadbackDisposition::ExactVersion, digest(16)).unwrap(),
    )
    .unwrap();
    let readiness = CredentialReadinessObservation::new(
        operation(41),
        Some(operation(11)),
        provider(),
        CredentialLifecycleRevision::new(3).unwrap(),
        CredentialReadinessRevision::new(3).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(CredentialBindingDigest::from_measured(*active.ref_digest()).unwrap()),
        qualified_release(92).digest(),
        100,
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::complete(
        store,
        CompleteCredentialOperation::new(
            operation(11),
            BindCredentialReadback::new(operation(11), CredentialReadbackDisposition::ExactVersion, digest(16)).unwrap(),
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialFence::new(2).unwrap(),
        )
        .unwrap()
        .with_readiness_observation(readiness),
    )
    .unwrap();
}

fn prepare_retired_cleanup(
    store: &super::SqliteProviderCredentialLifecycleStore,
    retired: &CredentialVersionRef,
) {
    store.connection.lock().unwrap().execute(
        "INSERT INTO provider_credential_operations
         (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
          expected_lifecycle_revision, expected_credential_fence, target_credential_version,
          target_ref_digest, state, begin_proof_digest, begin_proof_expires_at_high_water,
          qualified_release_tuple_digest, created_at, updated_at)
         VALUES (?1, ?2, 'openai', 'RETIRED_VERSION_CLEANUP', ?3, 'retired-cleanup',
                 3, 3, ?4, ?5, 'PREPARED', ?6, 200, ?7, 100, 100)",
        rusqlite::params![
            operation(12).as_bytes().as_slice(),
            CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap().as_bytes().as_slice(),
            CommandId::from_bytes([32; 16]).as_bytes().as_slice(),
            retired.version(),
            retired.ref_digest().to_vec(),
            digest(17).as_bytes().as_slice(),
            qualified_release(92).digest().as_bytes().as_slice(),
        ],
    ).unwrap();
    let receipt = issue_ticket(store, ticket(12, 1, 18, 19)).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        store,
        seal_claim(store, ClaimCredentialOperation::new(receipt, digest(18), digest(19), digest(20), 1, 1).unwrap()),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        store,
        ObserveNativeEffect::new(operation(12), CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        store,
        BindCredentialReadback::new(operation(12), CredentialReadbackDisposition::ExactAbsence, digest(21)).unwrap(),
    )
    .unwrap();
}

fn cleanup_completion() -> CompleteCredentialOperation {
    let active = CredentialVersionRef::new(provider(), 2).unwrap();
    let readiness = CredentialReadinessObservation::new(
        operation(42),
        Some(operation(12)),
        provider(),
        CredentialLifecycleRevision::new(4).unwrap(),
        CredentialReadinessRevision::new(4).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(CredentialBindingDigest::from_measured(*active.ref_digest()).unwrap()),
        qualified_release(92).digest(),
        100,
    )
    .unwrap();
    CompleteCredentialOperation::new(
        operation(12),
        BindCredentialReadback::new(operation(12), CredentialReadbackDisposition::ExactAbsence, digest(21)).unwrap(),
        CredentialLifecycleRevision::new(3).unwrap(),
        CredentialFence::new(3).unwrap(),
    )
    .unwrap()
    .with_readiness_observation(readiness)
}

fn version_state(store: &super::SqliteProviderCredentialLifecycleStore, version: u64) -> String {
    store.connection.lock().unwrap().query_row(
        "SELECT lifecycle_state FROM provider_credential_versions
         WHERE provider_id='openai' AND credential_version=?1",
        [version],
        |row| row.get(0),
    ).unwrap()
}

fn readiness(store: &super::SqliteProviderCredentialLifecycleStore) -> (i64, i64, Vec<u8>, Vec<u8>) {
    store.connection.lock().unwrap().query_row(
        "SELECT lifecycle_revision, readiness_revision, active_binding_digest, operation_id
         FROM provider_credential_readiness_observations WHERE observation_id=?1",
        [operation(42).as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap()
}
