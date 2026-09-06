use std::fmt;

use crate::{
    PendingQualificationAdmission, QualificationFaultVerifier, QualificationRunContextVerifier,
};

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

    /// Authenticates and consumes a pair against caller-owned installed facts.
    ///
    /// # Errors
    ///
    /// Rejects unavailable authorities, invalid signatures, time, replay, any
    /// installed-fact mismatch, or any context-to-ticket assertion mismatch.
    pub fn verify_and_consume(
        &mut self,
        admission: PendingQualificationAdmission,
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<(), QualificationAdmissionVerificationError> {
        if candidate_sha256 == [0; 32] || raw_v3_tuple_sha256 == [0; 32] {
            return Err(QualificationAdmissionVerificationError);
        }
        let (context, fault) = admission.into_verification_members();
        let (_context, expected) = self
            .context
            .verify_installed_and_consume(
                &context.into_admitted_bytes(),
                candidate_sha256,
                raw_v3_tuple_sha256,
                now_unix_seconds,
            )
            .map_err(|_| QualificationAdmissionVerificationError)?;
        let fault = self
            .fault
            .verify_and_consume(&fault.into_admitted_bytes(), &expected, now_unix_seconds)
            .map_err(|_| QualificationAdmissionVerificationError)?;
        let _ = fault;
        Ok(())
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

/// Closed combined-admission rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAdmissionVerificationError;

impl fmt::Display for QualificationAdmissionVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification admission verification rejected")
    }
}

impl std::error::Error for QualificationAdmissionVerificationError {}
