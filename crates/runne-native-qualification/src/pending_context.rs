/// Opaque canonical runner context retained after authenticated relay admission.
pub struct PendingQualificationRunContext {
    bytes: Vec<u8>,
}

impl PendingQualificationRunContext {
    pub(crate) fn from_admitted_frame(
        bytes: Vec<u8>,
    ) -> Result<Self, crate::QualificationRunContextError> {
        let context = crate::context_wire::decode(&bytes)?;
        crate::context_verification::validate_admitted_shape(
            &context,
            crate::QualificationRunContextError::InvalidContext,
        )?;
        Ok(Self { bytes })
    }

    pub(crate) fn encode_relay(
        self,
        codec: &crate::QualificationRunContextRelayCodecV1,
        binding: &runne_api::QualificationRunContextRelayBindingV1,
    ) -> Result<Vec<u8>, crate::QualificationRunContextRelayError> {
        codec.encode_context(binding, &self.bytes)
    }
}
