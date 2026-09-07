use runne_native_qualification::{
    PendingQualificationAdmission, QualificationAdmissionVerifier, VerifiedQualificationFault,
};

use super::super::PendingCredentialIssueTicketV1;
use super::{CredentialWriterQualifiedPreludeV1, SignedCredentialWriterSessionAttestationV2};
use crate::credential::enrollment::CredentialEnrollmentError;

pub(crate) struct WriterQualificationReceiver {
    attestation: SignedCredentialWriterSessionAttestationV2,
    installed: Option<InstalledQualificationFacts>,
}

struct InstalledQualificationFacts {
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
    verifier: QualificationAdmissionVerifier,
}

pub(crate) struct VerifiedWriterPrelude {
    pub(crate) attestation_digest: [u8; 32],
    pub(crate) prelude_digest: [u8; 32],
    pub(crate) fault: VerifiedWriterQualificationFault,
}

#[allow(dead_code, reason = "Task 3 consumes this receiver-owned fault")]
pub(crate) struct VerifiedWriterQualificationFault(VerifiedQualificationFault);

impl WriterQualificationReceiver {
    pub(crate) const fn new(attestation: SignedCredentialWriterSessionAttestationV2) -> Self {
        Self {
            attestation,
            installed: None,
        }
    }

    pub(crate) fn bind_verified_release(
        self,
        release: &runne_api::VerifiedSignedInstalledReleaseV2,
    ) -> Result<Self, CredentialEnrollmentError> {
        self.bind_release_with_verifier(
            release,
            QualificationAdmissionVerifier::from_compiled_policy(),
        )
    }

    fn bind_release_with_verifier(
        mut self,
        release: &runne_api::VerifiedSignedInstalledReleaseV2,
        verifier: QualificationAdmissionVerifier,
    ) -> Result<Self, CredentialEnrollmentError> {
        let tuple = release
            .native_enrollment_tuple_v3()
            .ok_or(CredentialEnrollmentError::InvalidEvidence)?;
        self.installed = Some(InstalledQualificationFacts {
            candidate_sha256: tuple.candidate_digest(),
            raw_v3_tuple_sha256: tuple.tuple_digest(),
            verifier,
        });
        Ok(self)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn bind_test_verified_release(
        self,
        release: &runne_api::VerifiedSignedInstalledReleaseV2,
        verifier: QualificationAdmissionVerifier,
    ) -> Result<Self, CredentialEnrollmentError> {
        self.bind_release_with_verifier(release, verifier)
    }

    pub(crate) const fn attestation(&self) -> &SignedCredentialWriterSessionAttestationV2 {
        &self.attestation
    }

    pub(crate) fn verify_prelude(
        self,
        prelude: CredentialWriterQualifiedPreludeV1,
        now_unix_seconds: u64,
    ) -> Result<VerifiedWriterPrelude, CredentialEnrollmentError> {
        if !self.attestation.is_current_now() || !prelude.matches_attestation(&self.attestation) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let prelude_digest = prelude.full_digest();
        let InstalledQualificationFacts {
            candidate_sha256,
            raw_v3_tuple_sha256,
            mut verifier,
        } = self
            .installed
            .ok_or(CredentialEnrollmentError::InvalidEvidence)?;
        let admission = PendingQualificationAdmission::from_admitted_bundle(prelude.bundle)
            .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?;
        let fault = verifier
            .verify_exact_writer_fault_borrowed(
                &admission,
                candidate_sha256,
                raw_v3_tuple_sha256,
                now_unix_seconds,
            )
            .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?;
        if !self.attestation.is_current_now() {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(VerifiedWriterPrelude {
            attestation_digest: self.attestation.full_digest(),
            prelude_digest,
            fault: VerifiedWriterQualificationFault(fault),
        })
    }
}

impl PendingCredentialIssueTicketV1 {
    /// Binds qualified verification only to already authenticated V3 release facts.
    #[doc(hidden)]
    pub fn bind_verified_qualification_release(
        mut self,
        release: &runne_api::VerifiedSignedInstalledReleaseV2,
    ) -> Result<Self, CredentialEnrollmentError> {
        if let Some(receiver) = self.take_qualified_receiver() {
            self.retain_qualified_receiver(receiver.bind_verified_release(release)?);
        }
        Ok(self)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn bind_test_verified_qualification_release(
        mut self,
        release: &runne_api::VerifiedSignedInstalledReleaseV2,
        verifier: QualificationAdmissionVerifier,
    ) -> Result<Self, CredentialEnrollmentError> {
        if let Some(receiver) = self.take_qualified_receiver() {
            self.retain_qualified_receiver(receiver.bind_test_verified_release(release, verifier)?);
        }
        Ok(self)
    }
}
