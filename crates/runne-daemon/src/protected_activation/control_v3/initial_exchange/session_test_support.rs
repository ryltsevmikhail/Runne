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

pub(crate) struct ConnectedQualificationFixture {
    pub(crate) installed: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    pub(crate) admission: super::VerifiedQualificationAdmission,
    pub(crate) verifier: runne_native_qualification::QualificationAdmissionVerifier,
    receiver: ConnectedQualificationReceiver,
    pub(crate) now: u64,
}

pub(crate) struct ConnectedQualificationReceiver {
    release: runne_api::VerifiedSignedInstalledReleaseV2,
    verifier: runne_native_qualification::QualificationAdmissionVerifier,
}

impl ConnectedQualificationFixture {
    pub(crate) fn into_parts(
        self,
    ) -> (
        runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        super::VerifiedQualificationAdmission,
        runne_native_qualification::QualificationAdmissionVerifier,
        ConnectedQualificationReceiver,
        u64,
    ) {
        (
            self.installed,
            self.admission,
            self.verifier,
            self.receiver,
            self.now,
        )
    }
}

impl ConnectedQualificationReceiver {
    pub(crate) fn into_parts(
        self,
    ) -> (
        runne_api::VerifiedSignedInstalledReleaseV2,
        runne_native_qualification::QualificationAdmissionVerifier,
    ) {
        (self.release, self.verifier)
    }
}

pub(crate) fn connected_qualification_fixture(
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    release: runne_api::VerifiedSignedInstalledReleaseV2,
) -> ConnectedQualificationFixture {
    let tuple = release.native_enrollment_tuple_v3().unwrap();
    let installed = runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts::test_only_qualification_facts(
        *owned.enrollment_binding().release_tuple_digest(),
        *owned.enrollment_binding().qualification_binding_digest(),
        tuple.candidate_digest(),
        tuple.tuple_digest(),
    );
    let context = SigningKey::from_bytes(&[7; 32]);
    let fault = SigningKey::from_bytes(&[9; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bundle = super::writer_admission_bundle_for_at(
        &context,
        &fault,
        now,
        tuple.candidate_digest(),
        tuple.tuple_digest(),
    );
    let mut verifier =
        runne_native_qualification::QualificationAdmissionVerifier::test_only_from_verifying_keys(
            context.verifying_key(),
            fault.verifying_key(),
        );
    let admission = super::verify_and_retain_qualification_admission_for_test(
        &installed,
        owned,
        &mut verifier,
        runne_native_qualification::PendingQualificationAdmission::from_admitted_bundle(
            bundle.clone(),
        )
        .unwrap(),
        super::qualification_fence::QualificationAdmissionMembers::from_test_bundle(&bundle)
            .unwrap(),
        now,
    )
    .unwrap();
    ConnectedQualificationFixture {
        installed,
        admission,
        verifier: runne_native_qualification::QualificationAdmissionVerifier::test_only_from_verifying_keys(context.verifying_key(), fault.verifying_key()),
        receiver: ConnectedQualificationReceiver {
            release,
            verifier: runne_native_qualification::QualificationAdmissionVerifier::test_only_from_verifying_keys(
                context.verifying_key(),
                fault.verifying_key(),
            ),
        },
        now,
    }
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
        super::qualification_admission_tests::support::writer_admission_at(
            &context_key,
            &fault_key,
            now,
        ),
        super::qualification_fence::QualificationAdmissionMembers::from_test_bundle(
            &super::qualification_admission_tests::support::writer_admission_bundle_at(
                &context_key,
                &fault_key,
                now,
            ),
        )
        .unwrap(),
        now,
    )
    .unwrap();
    let mut directory = tempfile::tempdir().unwrap();
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (mut authority, mut measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let mut store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &{
                let daemon = directory.path().join("runne-daemon");
                std::fs::create_dir_all(&daemon).unwrap();
                daemon.join("broker.sqlite")
            },
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
        .start_protected_session_with_controls(
            &keys,
            &owned,
            DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
            Vec::new(),
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
