/// Opaque canonical signed bootstrap proof awaiting exact verification.
pub struct PendingQualificationRunBootstrapProof {
    bytes: Vec<u8>,
}

impl PendingQualificationRunBootstrapProof {
    /// Admits only one closed canonical proof frame; it does not verify authority.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical shape, invalid fields, or oversized input.
    pub fn from_signed_bytes(
        bytes: Vec<u8>,
    ) -> Result<Self, crate::QualificationRunBootstrapError> {
        let _ = crate::bootstrap_wire::decode(&bytes)?;
        Ok(Self { bytes })
    }

    pub(crate) fn verify_and_consume(
        self,
        verifier: &mut crate::QualificationRunBootstrapVerifier,
        expected: &crate::QualificationRunBootstrapExpectation,
        now_unix_seconds: u64,
    ) -> Result<crate::VerifiedQualificationRunBootstrapProof, crate::QualificationRunBootstrapError>
    {
        verifier.verify_bytes_and_consume(&self.bytes, expected, now_unix_seconds)
    }
}
