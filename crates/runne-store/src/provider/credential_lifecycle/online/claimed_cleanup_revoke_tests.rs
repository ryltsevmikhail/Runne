#[test]
fn revoke_fences_while_retired_cleanup_is_already_claimed() {
    let store = store();
    complete_pair(&store, 10, "first-pair-claimed-cleanup");
    let active = CredentialVersionRef::new(provider(), 2).unwrap();
    complete_version_two(&store, &active).unwrap();
    let owner = CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap();
    let cleanup = store
        .prepared_cleanup_operations(owner, &provider())
        .unwrap()
        .pop()
        .unwrap()
        .operation_id();
    let receipt = issue_ticket(
        &store,
        runne_provider::IssueCredentialTicketDigest::new(
            cleanup,
            digest(80),
            digest(81),
            100,
        )
        .unwrap(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(
            &store,
            ClaimCredentialOperation::new(receipt, digest(80), digest(81), digest(82), 1, 1)
                .unwrap(),
        ),
    )
    .unwrap();

    ProviderCredentialEnrollmentStore::begin(
        &store,
        revoke_after_rotation(operation(83), active, 84, "revoke-claimed-cleanup", 85),
    )
    .unwrap();

    let head = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    assert!(head.active_version().is_none());
    assert_eq!(head.lifecycle_revision().get(), 4);
    assert_eq!(head.fence().get(), 4);
    assert_eq!(
        store.load_operation(cleanup).unwrap().state(),
        runne_provider::CredentialOperationState::Claimed
    );

    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(cleanup, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    let superseded = ProviderCredentialEnrollmentStore::bind_readback(
        &store,
        BindCredentialReadback::new(
            cleanup,
            CredentialReadbackDisposition::ExactAbsence,
            digest(86),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        superseded.state(),
        runne_provider::CredentialOperationState::Failed
    );
    let successor = prepare_retired_cleanup(&store, &CredentialVersionRef::new(provider(), 1).unwrap());
    assert!(ProviderCredentialEnrollmentStore::complete(
        &store,
        cleanup_after_revoke_completion(successor),
    ).is_err());

    complete_revoke(&store, operation(83));
    ProviderCredentialEnrollmentStore::complete(
        &store,
        cleanup_after_revoke_completion(successor),
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
fn revoke_rejects_readback_verified_cleanup_without_fencing() {
    let store = store();
    complete_pair(&store, 10, "first-pair-readback-cleanup");
    let active = CredentialVersionRef::new(provider(), 2).unwrap();
    complete_version_two(&store, &active).unwrap();
    let cleanup = prepare_retired_cleanup(
        &store,
        &CredentialVersionRef::new(provider(), 1).unwrap(),
    );

    assert!(
        ProviderCredentialEnrollmentStore::begin(
            &store,
            revoke_after_rotation(operation(87), active.clone(), 88, "revoke-readback-cleanup", 89),
        )
        .is_err()
    );

    let head = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    assert_eq!(head.active_version(), Some(&active));
    assert_eq!(head.lifecycle_revision().get(), 3);
    assert_eq!(head.fence().get(), 3);
    assert_eq!(
        store.load_operation(cleanup).unwrap().state(),
        runne_provider::CredentialOperationState::ReadbackVerified
    );
}
