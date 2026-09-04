use super::*;
use runne_provider::{CredentialLifecycleError, CredentialOperationId};

#[path = "legacy_cleanup_reopen_tests.rs"]
mod reopen;
#[path = "legacy_cleanup_duplicate_tests.rs"]
mod duplicate;
#[path = "legacy_cleanup_recovery_rotation_tests.rs"]
mod recovery_rotation;

#[test]
fn legacy_cleanup_binding_retains_completed_import_after_active_version_changes() {
    let store = store();
    let cleanup = complete_import(&store);
    let before = ProviderCredentialEnrollmentStore::load_operation(&store, cleanup).unwrap();
    let binding = before.metadata().legacy_cleanup_binding().unwrap();
    assert_eq!(binding.import_operation_id(), operation(60));
    assert_eq!(binding.destination(), &CredentialVersionRef::new(provider(), 1).unwrap());
    assert_eq!(binding.observation_digest(), digest(65));
    let command_before = runne_provider::CredentialBrokerCommand::from_operation(
        &before, runne_provider::CredentialTicketAttempt::new(1).unwrap(),
    ).unwrap();
    assert_eq!(command_before.target(), &runne_provider::CredentialBrokerTarget::ExactLegacySource(binding.clone()));

    rotate_after_import(&store);
    let after = ProviderCredentialEnrollmentStore::load_operation(&store, cleanup).unwrap();
    assert_eq!(after.metadata().legacy_cleanup_binding(), Some(binding));
    assert_eq!(
        runne_provider::CredentialBrokerCommand::from_operation(&after, runne_provider::CredentialTicketAttempt::new(1).unwrap()).unwrap(),
        command_before,
    );
}

fn rotate_after_import(store: &super::super::SqliteProviderCredentialLifecycleStore) {
    let replacement = CredentialVersionRef::new(provider(), 2).unwrap();
    let begin = BeginCredentialOperation::new(
        CommandId::from_bytes([80; 16]), IdempotencyKey::new("post-import-rotation").unwrap(),
        operation(80), CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        provider(), CredentialOperationAction::Pair, Some(replacement.clone()), None,
        CredentialLifecycleRevision::new(2).unwrap(), CredentialFence::new(2).unwrap(),
        digest(81), 200,
    ).unwrap().with_qualified_release_tuple(qualified_release(92));
    ProviderCredentialEnrollmentStore::begin(store, begin).unwrap();
    issue_ticket(store, ticket(80, 1, 82, 83)).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        store, seal_claim(store, claim(store, 80, 1, 82, 83, 84)),
    ).unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        store, ObserveNativeEffect::new(operation(80), CredentialNativeEffectDisposition::PossibleEffect),
    ).unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        store, BindCredentialReadback::new(operation(80), CredentialReadbackDisposition::ExactVersion, digest(85)).unwrap(),
    ).unwrap();
    let readiness = CredentialReadinessObservation::new(
        operation(180), Some(operation(80)), provider(), CredentialLifecycleRevision::new(3).unwrap(),
        CredentialReadinessRevision::new(3).unwrap(), CredentialReadinessDisposition::Ready,
        Some(digest_from(&replacement)), qualified_release(92).digest(), 100,
    ).unwrap();
    let completion = CompleteCredentialOperation::new(
        operation(80), BindCredentialReadback::new(operation(80), CredentialReadbackDisposition::ExactVersion, digest(85)).unwrap(),
        CredentialLifecycleRevision::new(2).unwrap(), CredentialFence::new(2).unwrap(),
    ).unwrap().with_readiness_observation(readiness);
    ProviderCredentialEnrollmentStore::complete_with_receipt(store, completion).unwrap();
    assert_eq!(
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(store, &provider()).unwrap().active_version(),
        Some(&replacement),
    );
}

#[test]
fn legacy_cleanup_binding_rejects_corrupt_consumed_digest() {
    let store = store();
    let cleanup = complete_import(&store);
    // Simulate corrupt durable storage, not an allowed lifecycle transition.
    let connection = store.connection.lock().unwrap();
    connection.execute_batch("DROP TRIGGER provider_credential_head_monotonic").unwrap();
    connection.execute(
        "UPDATE provider_credential_authority_heads SET legacy_source_binding_digest=?1
         WHERE provider_id='openai'",
        [digest(99).as_bytes().as_slice()],
    ).unwrap();
    drop(connection);
    assert_eq!(
        ProviderCredentialEnrollmentStore::load_operation(&store, cleanup),
        Err(CredentialLifecycleError::CorruptState),
    );
}

#[test]
fn legacy_cleanup_binding_rejects_consumed_revision_without_matching_import() {
    let store = store();
    let cleanup = complete_import(&store);
    let connection = store.connection.lock().unwrap();
    // Corruption fixture only: normal writes cannot alter the consumed barrier.
    connection.execute_batch("DROP TRIGGER provider_credential_head_monotonic").unwrap();
    connection.execute(
        "UPDATE provider_credential_authority_heads SET legacy_consumed_lifecycle_revision=3,
         lifecycle_revision=3 WHERE provider_id='openai'", [],
    ).unwrap();
    drop(connection);
    assert_eq!(ProviderCredentialEnrollmentStore::load_operation(&store, cleanup),
        Err(CredentialLifecycleError::CorruptState));
}

#[test]
fn legacy_cleanup_binding_rejects_missing_original_import() {
    let store = store();
    let cleanup = complete_import(&store);
    let connection = store.connection.lock().unwrap();
    // Deliberately corrupt this disposable fixture, bypassing normal permanence.
    connection.execute_batch("PRAGMA foreign_keys=OFF; DROP TRIGGER provider_credential_operation_permanent").unwrap();
    assert_eq!(connection.execute(
        "DELETE FROM provider_credential_operations WHERE operation_id=?1",
        [operation(60).as_bytes().as_slice()],
    ).unwrap(), 1);
    connection.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    drop(connection);
    assert_eq!(ProviderCredentialEnrollmentStore::load_operation(&store, cleanup),
        Err(CredentialLifecycleError::CorruptState));
}

#[test]
fn legacy_cleanup_binding_survives_successful_import_tombstone() {
    let store = store();
    let cleanup = complete_import(&store);
    let before = ProviderCredentialEnrollmentStore::load_operation(&store, cleanup).unwrap();
    ProviderCredentialEnrollmentStore::tombstone(
        &store,
        runne_provider::TombstoneCredentialOperation::new(operation(60), CredentialOperationState::Completed).unwrap(),
    ).unwrap();
    let after = ProviderCredentialEnrollmentStore::load_operation(&store, cleanup).unwrap();
    assert_eq!(after.metadata().legacy_cleanup_binding(), before.metadata().legacy_cleanup_binding());
    assert!(after.metadata().legacy_cleanup_binding().is_some());
}

#[test]
fn legacy_cleanup_binding_rejects_wrong_cleanup_identity_and_owner() {
    let store = store();
    let cleanup = complete_import(&store);
    let snapshot = ProviderCredentialEnrollmentStore::load_operation(&store, cleanup).unwrap();
    let original = snapshot.metadata();
    let connection = store.connection.lock().unwrap();
    for (id, command, owner, lifecycle, fence) in [
        (operation(99), original.command_id(), [42; 32], 2, 2),
        (cleanup, CommandId::from_bytes([99; 16]), [42; 32], 2, 2),
        (cleanup, original.command_id(), [99; 32], 2, 2),
        (cleanup, original.command_id(), [42; 32], 3, 2),
        (cleanup, original.command_id(), [42; 32], 2, 3),
    ] {
        let substituted = runne_provider::CredentialOperationMetadata::new(
            command, original.idempotency_key().clone(),
            CredentialInstallationOwnerId::from_bytes(owner).unwrap(),
            CredentialLifecycleRevision::new(lifecycle).unwrap(), CredentialFence::new(fence).unwrap(),
            original.begin_proof_digest(), original.created_at_high_water(), original.updated_at_high_water(),
        ).unwrap();
        assert_eq!(
            super::super::legacy_cleanup_binding::load(
                &connection, &store.enrollment_authority, id, &provider(), &substituted,
            ),
            Err(CredentialLifecycleError::CorruptState),
        );
    }
}

fn complete_import(store: &super::super::SqliteProviderCredentialLifecycleStore) -> CredentialOperationId {
    ProviderCredentialEnrollmentStore::begin(store, authorized_legacy_begin(store)).unwrap();
    issue_ticket(store, ticket(60, 1, 61, 62)).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        store, seal_claim(store, claim(store, 60, 1, 61, 62, 63)),
    ).unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        store, ObserveNativeEffect::new(operation(60), CredentialNativeEffectDisposition::PossibleEffect),
    ).unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        store,
        BindCredentialReadback::new(operation(60), CredentialReadbackDisposition::ExactVersion, digest(65)).unwrap(),
    ).unwrap();
    ProviderCredentialEnrollmentStore::complete_with_receipt(store, pair_completion(60)).unwrap();
    let id: Vec<u8> = store.connection.lock().unwrap().query_row(
        "SELECT legacy_cleanup_operation_id FROM provider_credential_authority_heads WHERE provider_id='openai'",
        [], |row| row.get(0),
    ).unwrap();
    CredentialOperationId::from_bytes(id.try_into().unwrap()).unwrap()
}
