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

include!("recovery_ledger_tests.rs");
include!("recovery_admission_tests.rs");
include!("recovery_claim_tests.rs");

#[test]
fn rotation_creates_one_durable_retired_cleanup_without_test_insertion() {
    let store = store();
    complete_pair(&store, 10, "first-pair");
    let active = CredentialVersionRef::new(provider(), 2).unwrap();
    complete_version_two(&store, &active).unwrap();
    let cleanups: Vec<(i64, String)> = store.connection.lock().unwrap()
        .prepare("SELECT target_credential_version, state FROM provider_credential_operations
                  WHERE provider_id='openai' AND action='RETIRED_VERSION_CLEANUP'")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(cleanups, vec![(1, "PREPARED".to_owned())]);
    let head = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider())
        .unwrap();
    assert_eq!(head.active_version(), Some(&active));
    let owner = CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap();
    let pending = store.prepared_cleanup_operations(owner, &provider()).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action(), CredentialOperationAction::RetiredVersionCleanup);
    assert_eq!(pending[0].target_credential_version().unwrap().version(), 1);
    assert!(store.prepared_cleanup_operations(
        CredentialInstallationOwnerId::from_bytes([43; 32]).unwrap(), &provider(),
    ).unwrap().is_empty());
    assert!(store.prepared_cleanup_operations(
        owner, &runne_provider::ProviderId::new("deepseek").unwrap(),
    ).unwrap().is_empty());
}

#[test]
fn retired_cleanup_completion_advances_authority_and_replays_exactly() {
    let store = store();
    let retired = CredentialVersionRef::new(provider(), 1).unwrap();
    let active = CredentialVersionRef::new(provider(), 2).unwrap();

    complete_pair(&store, 10, "first-pair");
    complete_version_two(&store, &active).unwrap();
    let cleanup = prepare_retired_cleanup(&store, &retired);

    let first = ProviderCredentialEnrollmentStore::complete_with_receipt(&store, cleanup_completion(cleanup))
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
        (4, 4, active.ref_digest().to_vec(), cleanup.as_bytes().to_vec())
    );

    let replay = ProviderCredentialEnrollmentStore::complete_with_receipt(&store, cleanup_completion(cleanup))
        .unwrap();
    assert_eq!(replay, first);
    assert!(store.prepared_cleanup_operations(
        CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(), &provider(),
    ).unwrap().is_empty());
}

fn complete_version_two(
    store: &super::SqliteProviderCredentialLifecycleStore,
    active: &CredentialVersionRef,
) -> Result<(), runne_provider::CredentialLifecycleError> {
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
    .map(|_| ())
}

#[test]
fn retired_cleanup_insert_failure_rolls_back_rotation_cutover() {
    let store = store();
    complete_pair(&store, 10, "first-pair");
    let before = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider())
        .unwrap();
    store.connection.lock().unwrap().execute_batch(
        "CREATE TEMP TRIGGER fail_retired_cleanup BEFORE INSERT ON provider_credential_operations
         WHEN NEW.action='RETIRED_VERSION_CLEANUP'
         BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END;",
    ).unwrap();
    let active = CredentialVersionRef::new(provider(), 2).unwrap();
    assert!(complete_version_two(&store, &active).is_err());
    let after = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider())
        .unwrap();
    assert_eq!(after.active_version(), before.active_version());
    assert_eq!(after.lifecycle_revision(), before.lifecycle_revision());
    assert_eq!(after.fence(), before.fence());
    assert_eq!(after.readiness_revision(), before.readiness_revision());
    // Claim allocated version 2 before cutover; rollback must not reuse it.
    assert_eq!(after.next_credential_version(), 3);
    assert_eq!(version_state(&store, 1), "ACTIVE");
    assert_eq!(ProviderCredentialEnrollmentStore::load_operation(&store, operation(11))
        .unwrap().state(), runne_provider::CredentialOperationState::ReadbackVerified);
}

fn prepare_retired_cleanup(
    store: &super::SqliteProviderCredentialLifecycleStore,
    retired: &CredentialVersionRef,
) -> runne_provider::CredentialOperationId {
    let bytes: Vec<u8> = store.connection.lock().unwrap().query_row(
        "SELECT operation_id FROM provider_credential_operations
         WHERE action='RETIRED_VERSION_CLEANUP' AND target_ref_digest=?1",
        [retired.ref_digest().as_slice()], |row| row.get(0),
    ).unwrap();
    let cleanup = runne_provider::CredentialOperationId::from_bytes(bytes.try_into().unwrap())
        .unwrap();
    let receipt = issue_ticket(store, runne_provider::IssueCredentialTicketDigest::new(
        cleanup, digest(18), digest(19), 100,
    ).unwrap()).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        store,
        seal_claim(store, ClaimCredentialOperation::new(receipt, digest(18), digest(19), digest(20), 1, 1).unwrap()),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        store,
        ObserveNativeEffect::new(cleanup, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        store,
        BindCredentialReadback::new(cleanup, CredentialReadbackDisposition::ExactAbsence, digest(21)).unwrap(),
    )
    .unwrap();
    cleanup
}

fn cleanup_completion(cleanup: runne_provider::CredentialOperationId) -> CompleteCredentialOperation {
    let active = CredentialVersionRef::new(provider(), 2).unwrap();
    let readiness = CredentialReadinessObservation::new(
        operation(42),
        Some(cleanup),
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
        cleanup,
        BindCredentialReadback::new(cleanup, CredentialReadbackDisposition::ExactAbsence, digest(21)).unwrap(),
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
