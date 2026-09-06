use crate::model::{
    QualificationFaultContext, QualificationFaultError, VerifiedQualificationFault,
};
use sha2::{Digest as _, Sha256};

/// Opaque canonical ticket retained between native admission and exact use.
pub struct PendingQualificationFault {
    bytes: Vec<u8>,
    expires_at: u64,
}

impl PendingQualificationFault {
    pub(crate) fn into_admitted_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn matches_sha256(&self, expected: &[u8; 32]) -> bool {
        Sha256::digest(&self.bytes).as_slice() == expected
    }

    pub(crate) const fn expires_no_earlier_than(&self, expires_at: u64) -> bool {
        expires_at <= self.expires_at
    }

    /// Retains one already-admitted canonical ticket frame without verifying
    /// authority or context.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, noncanonical, trailing, or semantically invalid input.
    pub fn from_admitted_frame(bytes: Vec<u8>) -> Result<Self, QualificationFaultError> {
        let ticket = crate::wire::decode(&bytes)?;
        crate::verification::validate_admitted_shape(
            &ticket,
            QualificationFaultError::InvalidTicket,
        )?;
        Ok(Self {
            bytes,
            expires_at: ticket.expires_at,
        })
    }

    /// Consumes this pending frame through the exact verifier and context.
    ///
    /// # Errors
    ///
    /// Returns the verifier's closed rejection without exposing retained bytes.
    pub fn verify_and_consume(
        self,
        verifier: &mut crate::QualificationFaultVerifier,
        context: &QualificationFaultContext,
        now_unix_seconds: u64,
    ) -> Result<VerifiedQualificationFault, QualificationFaultError> {
        verifier.verify_and_consume(&self.bytes, context, now_unix_seconds)
    }

    /// Consumes this carrier into the sole authenticated relay encoding path.
    ///
    /// # Errors
    ///
    /// Returns a closed relay rejection if the retained ticket cannot be
    /// represented by the exact bounded relay contract.
    pub fn encode_relay(
        self,
        codec: &crate::QualificationFaultRelayCodecV1,
        binding: &runne_api::QualificationFaultRelayBindingV1,
    ) -> Result<Vec<u8>, crate::QualificationFaultRelayError> {
        codec.encode_ticket(binding, &self.bytes)
    }
}
