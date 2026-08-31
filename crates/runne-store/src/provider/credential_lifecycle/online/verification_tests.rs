use runne_provider::{
    BeginCredentialVerification, CompleteCredentialVerification, CredentialFence,
    CredentialLifecycleError, CredentialLifecycleRevision, CredentialReadinessRevision,
    CredentialVerificationKind, CredentialVerificationObservation, CredentialVerificationResult,
    CredentialVerifierRevision, CredentialVersionRef, ProviderCredentialEnrollmentStore,
};

use super::online_test_support::{complete_pair, digest, operation, provider, store};

#[test]
fn credential_online_verification_requires_an_exact_active_ref() {
    let store = store();
    let begin = BeginCredentialVerification::new(
        operation(51),
        None,
        provider(),
        CredentialVerificationKind::Local,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialReadinessRevision::new(1).unwrap(),
        digest(53),
        digest(52),
        CredentialVerifierRevision::new(1).unwrap(),
        100,
        200,
    )
    .unwrap();

    assert_eq!(
        ProviderCredentialEnrollmentStore::begin_verification(&store, begin).unwrap_err(),
        CredentialLifecycleError::Conflict
    );
}

#[test]
fn credential_online_verification_persists_exact_active_ref_for_completion() {
    let store = store();
    complete_pair(&store, 50, "verify");
    let begin = BeginCredentialVerification::new(
        operation(52),
        Some(operation(50)),
        provider(),
        CredentialVerificationKind::Local,
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialFence::new(2).unwrap(),
        CredentialReadinessRevision::new(2).unwrap(),
        digest(92),
        digest(53),
        CredentialVerifierRevision::new(1).unwrap(),
        100,
        200,
    )
    .unwrap();
    let lease = ProviderCredentialEnrollmentStore::begin_verification(&store, begin).unwrap();
    assert_eq!(
        lease.active_credential_version(),
        &CredentialVersionRef::new(provider(), 1).unwrap()
    );
    let observation = CredentialVerificationObservation::new(
        operation(52),
        CredentialVerificationResult::Verified,
        150,
    )
    .unwrap();

    let result = ProviderCredentialEnrollmentStore::complete_verification(
        &store,
        CompleteCredentialVerification::new(
            observation,
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialFence::new(2).unwrap(),
        ),
    )
    .unwrap();

    assert_eq!(lease.observation_id(), result.observation_id());
}
