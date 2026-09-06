/// Opaque canonical runner context retained after authenticated relay admission.
pub struct PendingQualificationRunContext {
    bytes: Vec<u8>,
    ticket_sha256: [u8; 32],
    expires_at: u64,
}

impl PendingQualificationRunContext {
    pub(crate) fn verify_installed_borrowed(
        &self,
        verifier: &mut crate::QualificationRunContextVerifier,
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<
        (
            crate::VerifiedQualificationRunContext,
            crate::QualificationFaultContext,
        ),
        crate::QualificationRunContextError,
    > {
        verifier.verify_installed_and_consume(
            &self.bytes,
            candidate_sha256,
            raw_v3_tuple_sha256,
            now_unix_seconds,
        )
    }

    pub(crate) fn from_admitted_frame(
        bytes: Vec<u8>,
    ) -> Result<Self, crate::QualificationRunContextError> {
        let context = crate::context_wire::decode(&bytes)?;
        let shape = crate::context_verification::validate_admitted_shape(
            &context,
            crate::QualificationRunContextError::InvalidContext,
        )?;
        Ok(Self {
            bytes,
            ticket_sha256: shape.ticket_sha256,
            expires_at: context.expires_at,
        })
    }

    pub(crate) fn matches_fault(&self, fault: &crate::PendingQualificationFault) -> bool {
        fault.matches_sha256(&self.ticket_sha256) && fault.expires_no_earlier_than(self.expires_at)
    }

    pub(crate) fn encode_relay(
        self,
        codec: &crate::QualificationRunContextRelayCodecV1,
        binding: &runne_api::QualificationRunContextRelayBindingV1,
    ) -> Result<Vec<u8>, crate::QualificationRunContextRelayError> {
        codec.encode_context(binding, &self.bytes)
    }
}
