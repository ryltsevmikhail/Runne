use runne_provider::{
    BeginCredentialVerification, CredentialFence, CredentialLifecycleError,
    CredentialLifecycleRevision, CredentialReadinessRevision, CredentialVerificationKind,
    CredentialVerifierRevision, ProviderCredentialEnrollmentStore,
};

use super::online_test_support::{complete_pair, digest, operation, provider, store};

#[test]
fn verification_lease_rejects_a_stale_readiness_revision() {
    let store = store();
    complete_pair(&store, 81, "verification-binding");

    let stale_readiness = BeginCredentialVerification::new(
        operation(82),
        Some(operation(81)),
        provider(),
        CredentialVerificationKind::Local,
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialFence::new(2).unwrap(),
        CredentialReadinessRevision::new(1).unwrap(),
        digest(92),
        digest(83),
        CredentialVerifierRevision::new(1).unwrap(),
        100,
        200,
    )
    .unwrap();

    assert_eq!(
        ProviderCredentialEnrollmentStore::begin_verification(&store, stale_readiness),
        Err(CredentialLifecycleError::Conflict)
    );
}

#[test]
fn verification_lease_rejects_a_substituted_release_tuple() {
    let store = store();
    complete_pair(&store, 84, "verification-release-binding");

    let substituted_release = BeginCredentialVerification::new(
        operation(85),
        Some(operation(84)),
        provider(),
        CredentialVerificationKind::Local,
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialFence::new(2).unwrap(),
        CredentialReadinessRevision::new(2).unwrap(),
        digest(86),
        digest(87),
        CredentialVerifierRevision::new(1).unwrap(),
        100,
        200,
    )
    .unwrap();

    assert_eq!(
        ProviderCredentialEnrollmentStore::begin_verification(&store, substituted_release),
        Err(CredentialLifecycleError::Conflict)
    );
}
