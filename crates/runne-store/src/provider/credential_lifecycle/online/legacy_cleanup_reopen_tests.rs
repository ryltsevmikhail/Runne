use super::*;

#[test]
fn legacy_cleanup_completes_after_rotation_without_changing_active_head() {
    rotated_cleanup(false, false);
}

#[test]
fn legacy_cleanup_after_rotation_still_rejects_hard_fenced_head() {
    rotated_cleanup(true, false);
}

#[test]
fn legacy_cleanup_can_start_after_rotation() {
    rotated_cleanup(false, true);
}

fn rotated_cleanup(hard_fence: bool, rotate_before_claim: bool) {
    let store = store();
    let cleanup = complete_import(&store);
    if rotate_before_claim {
        rotate_after_import(&store);
    }
    let issued = issue_ticket(
        &store,
        runne_provider::IssueCredentialTicketDigest::new(cleanup, digest(71), digest(72), 100)
            .unwrap(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(
            &store,
            ClaimCredentialOperation::new(issued, digest(71), digest(72), digest(73), 1, 1)
                .unwrap(),
        ),
    )
    .unwrap();
    if !rotate_before_claim {
        rotate_after_import(&store);
    }
    let operation = ProviderCredentialEnrollmentStore::load_operation(&store, cleanup).unwrap();
    let command = runne_provider::CredentialBrokerCommand::from_operation(
        &operation,
        runne_provider::CredentialTicketAttempt::new(1).unwrap(),
    )
    .unwrap();
    let absence = runne_secure_store::ExactAbsenceReadback::new(command)
        .unwrap()
        .observe_service_presence(false)
        .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(cleanup, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    let readback = || {
        BindCredentialReadback::new(
            cleanup,
            CredentialReadbackDisposition::ExactAbsence,
            absence.binding(),
        )
        .unwrap()
    };
    ProviderCredentialEnrollmentStore::bind_readback(&store, readback()).unwrap();
    let completion = || {
        CompleteCredentialOperation::new(
            cleanup,
            readback(),
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialFence::new(2).unwrap(),
        )
        .unwrap()
    };
    if hard_fence {
        ProviderCredentialEnrollmentStore::hard_fence_provider(
            &store,
            runne_provider::HardFenceProvider::new(
                provider(),
                CredentialFence::new(3).unwrap(),
                CredentialFence::new(4).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            ProviderCredentialEnrollmentStore::complete_with_receipt(&store, completion()),
            Err(CredentialLifecycleError::Conflict)
        );
        assert_eq!(
            ProviderCredentialEnrollmentStore::load_operation(&store, cleanup)
                .unwrap()
                .state(),
            CredentialOperationState::ReadbackVerified
        );
        return;
    }
    let receipt =
        ProviderCredentialEnrollmentStore::complete_with_receipt(&store, completion()).unwrap();
    assert_eq!(receipt.predecessor_lifecycle_revision().get(), 2);
    assert_eq!(receipt.lifecycle_revision().get(), 3);
    assert_eq!(
        ProviderCredentialEnrollmentStore::complete_with_receipt(&store, completion()).unwrap(),
        receipt
    );
    let head = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    assert_eq!(head.lifecycle_revision().get(), 3);
    assert_eq!(head.fence().get(), 3);
    assert_eq!(
        head.active_version(),
        Some(&CredentialVersionRef::new(provider(), 2).unwrap())
    );
}

#[test]
fn legacy_cleanup_reopen_completes_bound_absence_without_reimport_or_head_change() {
    let store = store();
    let cleanup = complete_import(&store);
    let issued = issue_ticket(
        &store,
        runne_provider::IssueCredentialTicketDigest::new(cleanup, digest(71), digest(72), 100)
            .unwrap(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(
            &store,
            ClaimCredentialOperation::new(issued, digest(71), digest(72), digest(73), 1, 1)
                .unwrap(),
        ),
    )
    .unwrap();
    let before = ProviderCredentialEnrollmentStore::load_operation(&store, cleanup).unwrap();
    let head = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    let path = std::path::PathBuf::from(store.connection.lock().unwrap().path().unwrap());
    // The external delete is represented only by the later absence observation.
    // Drop/reopen exercises durable state, not a native Keychain crash qualification.
    drop(store);
    let reopened = super::super::super::online_claim_test_support::reopen_test_store(&path, 101);
    let work = ProviderCredentialEnrollmentStore::reconcile_online(&reopened, 101).unwrap();
    assert_eq!(work.len(), 1);
    let after = ProviderCredentialEnrollmentStore::load_operation(&reopened, cleanup).unwrap();
    assert_eq!(after.state(), CredentialOperationState::Claimed);
    assert_eq!(
        after.metadata().legacy_cleanup_binding(),
        before.metadata().legacy_cleanup_binding()
    );
    let command = runne_provider::CredentialBrokerCommand::from_operation(
        &after,
        runne_provider::CredentialTicketAttempt::new(1).unwrap(),
    )
    .unwrap();
    let absence = runne_secure_store::ExactAbsenceReadback::new(command)
        .unwrap()
        .observe_service_presence(false)
        .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &reopened,
        ObserveNativeEffect::new(cleanup, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    let readback = || {
        BindCredentialReadback::new(
            cleanup,
            CredentialReadbackDisposition::ExactAbsence,
            absence.binding(),
        )
        .unwrap()
    };
    ProviderCredentialEnrollmentStore::bind_readback(&reopened, readback()).unwrap();
    let completion = || {
        CompleteCredentialOperation::new(
            cleanup,
            readback(),
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialFence::new(2).unwrap(),
        )
        .unwrap()
    };
    let receipt =
        ProviderCredentialEnrollmentStore::complete_with_receipt(&reopened, completion()).unwrap();
    assert_eq!(
        ProviderCredentialEnrollmentStore::complete_with_receipt(&reopened, completion()).unwrap(),
        receipt
    );
    ProviderCredentialEnrollmentStore::tombstone(
        &reopened,
        runne_provider::TombstoneCredentialOperation::new(
            cleanup,
            CredentialOperationState::Completed,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        ProviderCredentialEnrollmentStore::reconcile_online(&reopened, 102)
            .unwrap()
            .is_empty()
    );
    let after_head =
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&reopened, &provider()).unwrap();
    assert_eq!(after_head.active_version(), head.active_version());
    let persisted: (i64, i64, i64, i64) = reopened
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT legacy_import_consumed, lifecycle_revision, credential_fence,
          (SELECT COUNT(*) FROM provider_credential_operations WHERE action='MIGRATE_LEGACY')
         FROM provider_credential_authority_heads WHERE provider_id='openai'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(persisted, (1, 2, 2, 1));
}
