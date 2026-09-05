#[test]
fn revoke_allows_preexisting_retired_cleanup_to_delete_every_native_version() {
    let store = store();
    complete_pair(&store, 10, "first-pair");
    let retired = CredentialVersionRef::new(provider(), 1).unwrap();
    let active = CredentialVersionRef::new(provider(), 2).unwrap();
    complete_version_two(&store, &active).unwrap();
    let before = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    assert_eq!(before.lifecycle_revision().get(), 3);
    assert_eq!(before.fence().get(), 3);
    assert_eq!(before.active_version(), Some(&active));

    let revoke = operation(50);
    ProviderCredentialEnrollmentStore::begin(
        &store,
        revoke_after_rotation(revoke, active, 51, "revoke-after-rotation", 52),
    )
    .unwrap();

    let receipt = issue_ticket(&store, ticket(50, 1, 53, 54)).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(
            &store,
            ClaimCredentialOperation::new(receipt, digest(53), digest(54), digest(55), 1, 1)
                .unwrap(),
        ),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(revoke, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        &store,
        BindCredentialReadback::new(
            revoke,
            CredentialReadbackDisposition::ExactAbsence,
            digest(56),
        )
        .unwrap(),
    )
    .unwrap();
    let readiness = CredentialReadinessObservation::new(
        operation(57),
        Some(revoke),
        provider(),
        CredentialLifecycleRevision::new(4).unwrap(),
        CredentialReadinessRevision::new(4).unwrap(),
        CredentialReadinessDisposition::Missing,
        None,
        qualified_release(92).digest(),
        100,
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::complete(
        &store,
        CompleteCredentialOperation::new(
            revoke,
            BindCredentialReadback::new(
                revoke,
                CredentialReadbackDisposition::ExactAbsence,
                digest(56),
            )
            .unwrap(),
            CredentialLifecycleRevision::new(3).unwrap(),
            CredentialFence::new(3).unwrap(),
        )
        .unwrap()
        .with_readiness_observation(readiness),
    )
    .unwrap();

    let cleanup = prepare_retired_cleanup(&store, &retired);
    ProviderCredentialEnrollmentStore::complete(
        &store,
        cleanup_after_revoke_completion(cleanup),
    )
    .unwrap();

    assert_eq!(version_state(&store, 1), "DELETED");
    assert_eq!(version_state(&store, 2), "DELETED");
    let head = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    assert!(head.active_version().is_none());
    assert_eq!(head.lifecycle_revision().get(), 5);
    assert_eq!(head.fence().get(), 5);
}

#[test]
fn revoke_supersedes_issued_retired_cleanup_ticket_atomically() {
    let store = store();
    complete_pair(&store, 10, "first-pair-issued-cleanup");
    let active = CredentialVersionRef::new(provider(), 2).unwrap();
    complete_version_two(&store, &active).unwrap();
    let owner = CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap();
    let cleanup = store
        .prepared_cleanup_operations(owner, &provider())
        .unwrap()
        .pop()
        .unwrap()
        .operation_id();
    issue_ticket(
        &store,
        runne_provider::IssueCredentialTicketDigest::new(
            cleanup,
            digest(70),
            digest(71),
            100,
        )
        .unwrap(),
    )
    .unwrap();

    ProviderCredentialEnrollmentStore::begin(
        &store,
        revoke_after_rotation(operation(72), active, 73, "revoke-issued-cleanup", 74),
    )
    .unwrap();

    assert_eq!(
        store.load_operation(cleanup).unwrap().state(),
        runne_provider::CredentialOperationState::Cancelled
    );
    let ticket_state: String = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT state FROM provider_credential_ticket_attempts WHERE operation_id=?1",
            [cleanup.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ticket_state, "TOMBSTONED");
}

#[test]
fn failed_revoke_insert_rolls_back_cleanup_supersession_and_fence() {
    let store = store();
    complete_pair(&store, 10, "first-pair-rollback");
    let active = CredentialVersionRef::new(provider(), 2).unwrap();
    complete_version_two(&store, &active).unwrap();
    let owner = CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap();
    let cleanup = store
        .prepared_cleanup_operations(owner, &provider())
        .unwrap()
        .pop()
        .unwrap()
        .operation_id();

    assert!(
        ProviderCredentialEnrollmentStore::begin(
            &store,
            revoke_after_rotation(operation(10), active.clone(), 75, "revoke-rollback", 76),
        )
        .is_err()
    );

    assert_eq!(
        store.load_operation(cleanup).unwrap().state(),
        runne_provider::CredentialOperationState::Prepared
    );
    let head = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    assert_eq!(head.active_version(), Some(&active));
    assert_eq!(head.lifecycle_revision().get(), 3);
    assert_eq!(head.fence().get(), 3);
}

fn revoke_after_rotation(
    operation_id: runne_provider::CredentialOperationId,
    active: CredentialVersionRef,
    command: u8,
    key: &str,
    proof: u8,
) -> BeginCredentialOperation {
    BeginCredentialOperation::new(
        CommandId::from_bytes([command; 16]),
        IdempotencyKey::new(key).unwrap(),
        operation_id,
        CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        provider(),
        CredentialOperationAction::Revoke,
        None,
        Some(active),
        CredentialLifecycleRevision::new(3).unwrap(),
        CredentialFence::new(3).unwrap(),
        digest(proof),
        200,
    )
    .unwrap()
    .with_qualified_release_tuple(qualified_release(92))
}

fn cleanup_after_revoke_completion(
    cleanup: runne_provider::CredentialOperationId,
) -> CompleteCredentialOperation {
    let readiness = CredentialReadinessObservation::new(
        operation(58),
        Some(cleanup),
        provider(),
        CredentialLifecycleRevision::new(5).unwrap(),
        CredentialReadinessRevision::new(5).unwrap(),
        CredentialReadinessDisposition::Missing,
        None,
        qualified_release(92).digest(),
        100,
    )
    .unwrap();
    CompleteCredentialOperation::new(
        cleanup,
        BindCredentialReadback::new(
            cleanup,
            CredentialReadbackDisposition::ExactAbsence,
            digest(21),
        )
        .unwrap(),
        CredentialLifecycleRevision::new(4).unwrap(),
        CredentialFence::new(4).unwrap(),
    )
    .unwrap()
    .with_readiness_observation(readiness)
}
