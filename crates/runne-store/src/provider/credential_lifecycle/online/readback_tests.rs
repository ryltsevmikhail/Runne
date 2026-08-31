use runne_provider::{
    BindCredentialReadback, CompleteCredentialOperation, CredentialBindingDigest, CredentialFence,
    CredentialLifecycleRevision, CredentialNativeEffectDisposition, CredentialOperationState,
    CredentialReadbackDisposition, CredentialReadinessDisposition, CredentialReadinessObservation,
    CredentialReadinessRevision, CredentialVersionRef, FailCredentialOperation,
    ObserveNativeEffect, ProviderCredentialEnrollmentStore,
};

use super::online_test_support::{admit_claim, digest, operation, provider, store};

#[test]
fn credential_online_failed_pair_reloads_exact_absence_disposition() {
    let store = store();
    admit_claim(&store, 96, "failed-pair-readback");

    let failed = ProviderCredentialEnrollmentStore::fail_with_verified_absence(
        &store,
        FailCredentialOperation::new(operation(96), digest(97)),
    )
    .unwrap();
    let reloaded =
        ProviderCredentialEnrollmentStore::load_operation(&store, operation(96)).unwrap();

    assert_eq!(failed.state(), CredentialOperationState::Failed);
    assert_eq!(
        failed.metadata().readback_disposition(),
        Some(CredentialReadbackDisposition::ExactAbsence)
    );
    assert_eq!(reloaded, failed);
}

#[test]
fn credential_online_pair_completion_rejects_opposite_readback_without_head_mutation() {
    let store = store();
    admit_claim(&store, 97, "opposite-completion-readback");
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(
            operation(97),
            CredentialNativeEffectDisposition::PossibleEffect,
        ),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        &store,
        BindCredentialReadback::new(
            operation(97),
            CredentialReadbackDisposition::ExactVersion,
            digest(98),
        )
        .unwrap(),
    )
    .unwrap();
    let before =
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();

    let result = ProviderCredentialEnrollmentStore::complete(&store, opposite_completion());

    assert_eq!(
        result.unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    assert_eq!(
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap(),
        before
    );
    assert_eq!(
        ProviderCredentialEnrollmentStore::load_operation(&store, operation(97))
            .unwrap()
            .state(),
        CredentialOperationState::ReadbackVerified
    );
}

fn opposite_completion() -> CompleteCredentialOperation {
    let active = CredentialVersionRef::new(provider(), 1).unwrap();
    let active_digest = CredentialBindingDigest::from_measured(*active.ref_digest()).unwrap();
    let readiness = CredentialReadinessObservation::new(
        operation(99),
        Some(operation(97)),
        provider(),
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialReadinessRevision::new(2).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(active_digest),
        digest(100),
        100,
    )
    .unwrap();
    CompleteCredentialOperation::new(
        operation(97),
        BindCredentialReadback::new(
            operation(97),
            CredentialReadbackDisposition::ExactAbsence,
            digest(98),
        )
        .unwrap(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
    )
    .unwrap()
    .with_readiness_observation(readiness)
}
