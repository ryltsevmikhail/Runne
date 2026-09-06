use std::fmt;

use crate::{
    PendingQualificationAdmission, QualificationFaultVerifier, QualificationRunContextVerifier,
    VerifiedQualificationFault, VerifiedQualificationRunContext,
};

/// Exact daemon-local installed facts allowed to constrain runner context.
pub struct QualificationRuntimeInstalledExpectation {
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
}

impl QualificationRuntimeInstalledExpectation {
    pub(crate) fn new(
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
    ) -> Result<Self, QualificationAdmissionVerificationError> {
        if candidate_sha256 == [0; 32] || raw_v3_tuple_sha256 == [0; 32] {
            return Err(QualificationAdmissionVerificationError);
        }
        Ok(Self {
            candidate_sha256,
            raw_v3_tuple_sha256,
        })
    }

    /// Seals an exact signed V3 candidate already bound to the owned session.
    #[doc(hidden)]
    #[must_use]
    pub fn from_verified_release_session(
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        candidate: &runne_api::SignedInstalledReleaseCandidateV3,
    ) -> Option<Self> {
        let binding = owned.enrollment_binding();
        let owned_release = *binding.release_tuple_digest();
        let owned_qualification = *binding.qualification_binding_digest();
        let signed_release = candidate.release_binding_digest();
        let signed_qualification = candidate.qualification_binding_digest();
        if owned_release != signed_release || owned_qualification != signed_qualification {
            return None;
        }
        Self::new(
            candidate.native_enrollment_tuple().candidate_digest(),
            candidate.native_enrollment_tuple().tuple_digest(),
        )
        .ok()
    }

    pub(crate) fn matches(&self, candidate: [u8; 32], raw_v3_tuple: [u8; 32]) -> bool {
        self.candidate_sha256 == candidate && self.raw_v3_tuple_sha256 == raw_v3_tuple
    }
}

/// Stateful, move-only verifier for one exact context-then-ticket admission.
pub struct QualificationAdmissionVerifier {
    context: QualificationRunContextVerifier,
    fault: QualificationFaultVerifier,
}

impl QualificationAdmissionVerifier {
    /// Loads the separately compiled context and fault authority policies.
    #[must_use]
    pub fn from_compiled_policy() -> Self {
        Self {
            context: QualificationRunContextVerifier::from_compiled_policy(),
            fault: QualificationFaultVerifier::from_compiled_policy(),
        }
    }

    /// Consumes and authenticates context first, then its exact bound ticket.
    ///
    /// # Errors
    ///
    /// Rejects unavailable authorities, invalid signatures, time, replay, any
    /// installed-fact mismatch, or any context-to-ticket assertion mismatch.
    pub fn verify_and_consume(
        &mut self,
        admission: PendingQualificationAdmission,
        installed: &QualificationRuntimeInstalledExpectation,
        now_unix_seconds: u64,
    ) -> Result<VerifiedQualificationAdmission, QualificationAdmissionVerificationError> {
        let (context, fault) = admission.into_verification_members();
        let (context, expected) = self
            .context
            .verify_installed_and_consume(
                &context.into_admitted_bytes(),
                installed,
                now_unix_seconds,
            )
            .map_err(|_| QualificationAdmissionVerificationError)?;
        let fault = self
            .fault
            .verify_and_consume(&fault.into_admitted_bytes(), &expected, now_unix_seconds)
            .map_err(|_| QualificationAdmissionVerificationError)?;
        Ok(VerifiedQualificationAdmission {
            _context: context,
            _fault: fault,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        context_key: ed25519_dalek::VerifyingKey,
        fault_key: ed25519_dalek::VerifyingKey,
    ) -> Self {
        use sha2::{Digest as _, Sha256};

        let distinct = context_key.as_bytes() != fault_key.as_bytes();
        let context = distinct.then(|| crate::context_policy::ContextVerificationPolicy {
            key_id: Sha256::digest(context_key.as_bytes()).into(),
            key: context_key,
        });
        let fault = distinct.then(|| crate::compiled_policy::FaultVerificationPolicy {
            key_id: Sha256::digest(fault_key.as_bytes()).into(),
            key: fault_key,
        });
        Self {
            context: QualificationRunContextVerifier::with_policy(context),
            fault: QualificationFaultVerifier::with_policy(fault),
        }
    }
}

/// Opaque verified pair. Task 2C owns its first consuming transition.
pub struct VerifiedQualificationAdmission {
    _context: VerifiedQualificationRunContext,
    _fault: VerifiedQualificationFault,
}

/// Closed combined-admission rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAdmissionVerificationError;

impl fmt::Display for QualificationAdmissionVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification admission verification rejected")
    }
}

impl std::error::Error for QualificationAdmissionVerificationError {}
