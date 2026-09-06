use crate::application::provider_credential_enrollment::{
    DaemonProtectedCredentialEnrollmentSession, DaemonProviderCredentialEnrollmentControl,
    broker::rendezvous::DaemonOwnedUnixBrokerRendezvous,
};
use ed25519_dalek::SigningKey;
use runne_provider::{CredentialAuthorityPair, CredentialEnrollmentAuthorityPair};
use runne_secure_store::{
    CredentialReadbackObservation, ExactAbsenceReadback, ExactVersionReadback,
    ProviderCredentialReadback, SecureStoreError,
};
use std::sync::Arc;

struct NoReadback;
pub(crate) fn owned_for_test() -> runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3 {
    crate::protected_activation::enrollment_v3_tests::owned_and_sessions().0
}
impl ProviderCredentialReadback for NoReadback {
    fn readback_exact_version(
        &self,
        _: ExactVersionReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        panic!("qualification must not reach native readback")
    }
    fn readback_exact_absence(
        &self,
        _: ExactAbsenceReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        panic!("qualification must not reach native readback")
    }
}

pub(crate) fn session(
    qualified: bool,
) -> (
    DaemonProtectedCredentialEnrollmentSession,
    runne_api::ProtectedActivationKeys,
    tempfile::TempDir,
) {
    session_with_active(qualified, false)
}

pub(crate) fn session_with_active(
    qualified: bool,
    active: bool,
) -> (
    DaemonProtectedCredentialEnrollmentSession,
    runne_api::ProtectedActivationKeys,
    tempfile::TempDir,
) {
    let (owned, keys, _) = crate::protected_activation::enrollment_v3_tests::owned_and_sessions();
    let installed = runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts::test_only_qualification_facts(
        *owned.enrollment_binding().release_tuple_digest(),
        *owned.enrollment_binding().qualification_binding_digest(), [0xaa; 32], [0xbb; 32],
    );
    let context_key = SigningKey::from_bytes(&[7; 32]);
    let fault_key = SigningKey::from_bytes(&[9; 32]);
    let mut verifier =
        runne_native_qualification::QualificationAdmissionVerifier::test_only_from_verifying_keys(
            context_key.verifying_key(),
            fault_key.verifying_key(),
        );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let admission = super::verify_and_retain_qualification_admission(
        &installed,
        &owned,
        &mut verifier,
        super::qualification_admission_tests::support::admission_at(&context_key, &fault_key, now),
        now,
    )
    .unwrap();
    let mut directory = tempfile::tempdir().unwrap();
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (mut authority, mut measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let mut store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &directory.path().join("broker.sqlite"),
            lifecycle,
            authority.clone(),
        )
        .unwrap();
    if active {
        let fixture = crate::application::provider_credential_enrollment::tests::broker_recovery_issue::fixture::completed_pair_fixture();
        store = fixture.store;
        authority = fixture.enrollment_authority;
        measurements = (*fixture.measurements).clone();
        directory = fixture._directory;
    }
    let control = Arc::new(
        DaemonProviderCredentialEnrollmentControl::new(
            Arc::new(store),
            Arc::new(NoReadback),
            measurements,
            authority,
            [9; 16],
            10,
            None,
        )
        .unwrap(),
    );
    let session = control
        .start_protected_session(
            &keys,
            &owned,
            DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
            installed,
        )
        .unwrap();
    let session = if qualified {
        session.retain_qualification(admission).unwrap()
    } else {
        session
    };
    (session, keys, directory)
}
