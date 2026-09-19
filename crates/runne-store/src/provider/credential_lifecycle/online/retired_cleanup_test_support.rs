fn prepare_retired_cleanup(
    store: &super::SqliteProviderCredentialLifecycleStore,
    retired: &CredentialVersionRef,
) -> runne_provider::CredentialOperationId {
    let bytes: Vec<u8> = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT operation_id FROM provider_credential_operations
         WHERE action='RETIRED_VERSION_CLEANUP' AND target_ref_digest=?1",
            [retired.ref_digest().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let cleanup =
        runne_provider::CredentialOperationId::from_bytes(bytes.try_into().unwrap()).unwrap();
    let receipt = issue_ticket(
        store,
        runne_provider::IssueCredentialTicketDigest::new(cleanup, digest(18), digest(19), 100)
            .unwrap(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::claim(
        store,
        seal_claim(
            store,
            ClaimCredentialOperation::new(receipt, digest(18), digest(19), digest(20), 1, 1)
                .unwrap(),
        ),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        store,
        ObserveNativeEffect::new(cleanup, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        store,
        BindCredentialReadback::new(
            cleanup,
            CredentialReadbackDisposition::ExactAbsence,
            digest(21),
        )
        .unwrap(),
    )
    .unwrap();
    cleanup
}

fn cleanup_completion(
    cleanup: runne_provider::CredentialOperationId,
) -> CompleteCredentialOperation {
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
        BindCredentialReadback::new(
            cleanup,
            CredentialReadbackDisposition::ExactAbsence,
            digest(21),
        )
        .unwrap(),
        CredentialLifecycleRevision::new(3).unwrap(),
        CredentialFence::new(3).unwrap(),
    )
    .unwrap()
    .with_readiness_observation(readiness)
}

fn version_state(store: &super::SqliteProviderCredentialLifecycleStore, version: u64) -> String {
    store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT lifecycle_state FROM provider_credential_versions
         WHERE provider_id='openai' AND credential_version=?1",
            [version],
            |row| row.get(0),
        )
        .unwrap()
}

fn readiness(
    store: &super::SqliteProviderCredentialLifecycleStore,
) -> (i64, i64, Vec<u8>, Vec<u8>) {
    store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT lifecycle_revision, readiness_revision, active_binding_digest, operation_id
         FROM provider_credential_readiness_observations WHERE observation_id=?1",
            [operation(42).as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}
