use runne_provider::{
    BeginCredentialVerification, CompleteCredentialVerification, CredentialFence,
    CredentialLifecycleRevision, CredentialReadinessDisposition, CredentialVerificationKind,
    CredentialVerificationObservation, CredentialVerificationResult, CredentialVerifierRevision,
    ProviderCredentialEnrollmentStore,
};

use super::online_test_support::{complete_pair, digest, operation, provider, store};

#[test]
fn safe_projection_exposes_only_current_readiness_and_no_verification() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin_admission_snapshot(&store, &provider()).unwrap();

    let missing = ProviderCredentialEnrollmentStore::safe_snapshot(&store, &provider()).unwrap();
    assert!(!missing.configured());
    assert_eq!(missing.readiness(), CredentialReadinessDisposition::Missing);
    assert_eq!(missing.verification().kind(), None);

    complete_pair(&store, 70, "safe-projection");
    let ready = ProviderCredentialEnrollmentStore::safe_snapshot(&store, &provider()).unwrap();
    assert!(ready.configured());
    assert_eq!(ready.lifecycle_revision().get(), 2);
    assert_eq!(ready.readiness(), CredentialReadinessDisposition::Ready);
    assert_eq!(ready.observed_at_high_water(), 100);
    assert!(!ready.verification().is_pending());
}

#[test]
fn safe_projection_uses_only_a_current_verification_observation() {
    let store = store();
    complete_pair(&store, 71, "safe-verification");
    let lease = ProviderCredentialEnrollmentStore::begin_verification(
        &store,
        BeginCredentialVerification::new(
            operation(75),
            Some(operation(71)),
            provider(),
            CredentialVerificationKind::Local,
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialFence::new(2).unwrap(),
            digest(76),
            CredentialVerifierRevision::new(4).unwrap(),
            100,
            200,
        )
        .unwrap(),
    )
    .unwrap();
    let pending = ProviderCredentialEnrollmentStore::safe_snapshot(&store, &provider()).unwrap();
    assert!(pending.verification().is_pending());
    assert_eq!(pending.verification().kind(), Some(CredentialVerificationKind::Local));

    ProviderCredentialEnrollmentStore::complete_verification(
        &store,
        CompleteCredentialVerification::new(
            CredentialVerificationObservation::new(
                lease.observation_id(),
                CredentialVerificationResult::Verified,
                150,
            )
            .unwrap(),
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialFence::new(2).unwrap(),
        ),
    )
    .unwrap();
    let completed = ProviderCredentialEnrollmentStore::safe_snapshot(&store, &provider()).unwrap();
    assert_eq!(
        completed.verification().result(),
        Some(CredentialVerificationResult::Verified)
    );
    assert_eq!(completed.verification().observed_at_high_water(), Some(150));
}
