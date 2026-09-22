use runne_native_qualification::{
    PendingQualificationAdmission, QualificationAdmissionVerifier, VerifiedQualificationFault,
};

use super::super::PendingCredentialIssueTicketV1;
use super::codec::CredentialWriterSessionAttestationV2Codec;
use super::{CredentialWriterQualifiedPreludeV1, SignedCredentialWriterSessionAttestationV2};
use crate::credential::enrollment::CredentialEnrollmentError;

#[cfg(all(test, target_os = "linux"))]
#[path = "receiver_linux_tests.rs"]
mod linux_tests;

/// Sealed verified Linux session record carried by the authority session.
///
/// Produced only by the authority-side verifier after the signature,
/// freshness, channel, handoff, and live-fact checks; the raw bytes never
/// re-enter verification on their own — `bind_to_ticket` re-verifies the
/// signature inside the provider against the RETAINED publication key and
/// re-binds the qualified receiver from the signed claims. No public raw
/// constructor and no public verify(record, caller-facts) minter exists.
/// Verifies the signed Linux record and re-binds the ticket's qualified
/// receiver from the signed claims; the content-pin token never leaves the
/// crate. Returns the bound ticket.
pub(crate) fn bind_verified_linux_attestation(
    ticket: PendingCredentialIssueTicketV1,
    bytes: &[u8],
    publication_key: [u8; 32],
    expected_release_tuple: [u8; 32],
) -> Result<PendingCredentialIssueTicketV1, CredentialEnrollmentError> {
    let attestation =
        CredentialWriterSessionAttestationV2Codec::decode_and_verify(bytes, publication_key)?;
    if !attestation.is_current_now()
        || attestation.claims.runtime.release_tuple.as_bytes() != expected_release_tuple
        || !attestation.matches_pending_issue_ticket(&ticket)
    {
        return Err(CredentialEnrollmentError::InvalidEvidence);
    }
    let candidate = attestation.claims.process.writer_image.as_bytes();
    let tuple = attestation.claims.runtime.release_tuple.as_bytes();
    // A wire-decoded IssueTicket has no receiver yet. Retain the verified
    // signed commitment before binding the local content pin; otherwise
    // claim_on silently selects the ordinary, unqualified protocol.
    let mut ticket = ticket.with_qualified_attestation(attestation);
    let receiver = ticket
        .take_qualified_receiver()
        .ok_or(CredentialEnrollmentError::InvalidEvidence)?;
    ticket.retain_qualified_receiver(receiver.bind_verified_content_pin(candidate, tuple)?);
    Ok(ticket)
}

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

    /// Linux equivalent of the signed-release binding: installs the SAME
    /// qualification facts from a daemon-attested local content pin
    /// (candidate image digest + tuple digest) with the same compiled
    /// verifier — an authoritative binding, not a bypass.
    fn bind_verified_content_pin(
        self,
        candidate_sha256: [u8; 32],
        raw_tuple_sha256: [u8; 32],
    ) -> Result<Self, CredentialEnrollmentError> {
        let verifier = QualificationAdmissionVerifier::from_compiled_policy();
        Ok(self.bind_release_facts(candidate_sha256, raw_tuple_sha256, verifier))
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

    fn bind_release_facts(
        mut self,
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        verifier: QualificationAdmissionVerifier,
    ) -> Self {
        self.installed = Some(InstalledQualificationFacts {
            candidate_sha256,
            raw_v3_tuple_sha256,
            verifier,
        });
        self
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
