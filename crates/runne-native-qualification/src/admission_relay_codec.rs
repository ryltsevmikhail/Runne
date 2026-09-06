use runne_api::{
    ProtectedActivationKeys, QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
    QualificationRunContextRelayBindingV1,
};

use crate::{
    PendingQualificationAdmission, PendingQualificationFault, PendingQualificationRunContext,
    QualificationAdmissionRelayError, QualificationAdmissionRelayTranscript,
    QualificationFaultRelayCodecV1, QualificationRunContextRelayCodecV1,
};

const OUTER_LENGTH_BYTES: usize = 4;
const MAX_CONTEXT_FRAME_BYTES: usize = 78 + crate::MAX_RUN_CONTEXT_BYTES + 32;
const MAX_FAULT_FRAME_BYTES: usize = 79 + crate::MAX_FAULT_TICKET_BYTES + 32;

/// One-key codec for the exact context-then-fault relay transcript.
pub struct QualificationAdmissionRelayCodecV1 {
    context: QualificationRunContextRelayCodecV1,
    fault: QualificationFaultRelayCodecV1,
}

impl QualificationAdmissionRelayCodecV1 {
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            context: QualificationRunContextRelayCodecV1::from_protected_activation(keys),
            fault: QualificationFaultRelayCodecV1::from_protected_activation(keys),
        }
    }

    pub(crate) fn encode(
        &self,
        context: PendingQualificationRunContext,
        fault: PendingQualificationFault,
        context_binding: &QualificationRunContextRelayBindingV1,
        fault_binding: &QualificationFaultRelayBindingV1,
    ) -> Result<QualificationAdmissionRelayTranscript, QualificationAdmissionRelayError> {
        validate_bindings(context_binding, fault_binding)?;
        let context_frame = context
            .encode_relay(&self.context, context_binding)
            .map_err(|_| QualificationAdmissionRelayError)?;
        let fault_frame = fault
            .encode_relay(&self.fault, fault_binding)
            .map_err(|_| QualificationAdmissionRelayError)?;
        let mut bytes =
            Vec::with_capacity(OUTER_LENGTH_BYTES * 2 + context_frame.len() + fault_frame.len());
        push_frame(&mut bytes, &context_frame)?;
        push_frame(&mut bytes, &fault_frame)?;
        Ok(QualificationAdmissionRelayTranscript::new(bytes))
    }

    /// Decodes exactly one context-first, fault-second transcript.
    ///
    /// # Errors
    ///
    /// Rejects mixed bindings or activations, missing/extra/reordered members,
    /// malformed outer lengths, inner authentication failure, and trailing data.
    pub fn decode_transcript(
        &self,
        bytes: &[u8],
        context_binding: &QualificationRunContextRelayBindingV1,
        fault_binding: &QualificationFaultRelayBindingV1,
    ) -> Result<PendingQualificationAdmission, QualificationAdmissionRelayError> {
        validate_bindings(context_binding, fault_binding)?;
        let (context_frame, fault_offset) = read_frame(bytes, 0, MAX_CONTEXT_FRAME_BYTES)?;
        let (fault_frame, end) = read_frame(bytes, fault_offset, MAX_FAULT_FRAME_BYTES)?;
        if end != bytes.len() {
            return Err(QualificationAdmissionRelayError);
        }
        let context = self
            .context
            .decode(context_frame, context_binding)
            .map_err(|_| QualificationAdmissionRelayError)?;
        let fault = self
            .fault
            .decode(fault_frame, fault_binding)
            .map_err(|_| QualificationAdmissionRelayError)?
            .ok_or(QualificationAdmissionRelayError)?;
        if !context.matches_fault(&fault) {
            return Err(QualificationAdmissionRelayError);
        }
        Ok(PendingQualificationAdmission::from_relay_members(
            context, fault,
        ))
    }
}

fn validate_bindings(
    context: &QualificationRunContextRelayBindingV1,
    fault: &QualificationFaultRelayBindingV1,
) -> Result<(), QualificationAdmissionRelayError> {
    if context.protected_session_id() != fault.protected_session_id()
        || context.release_tuple_v3_sha256() != fault.release_tuple_v3_sha256()
        || context.launch_generation() != fault.launch_generation()
        || fault.direction() != QualificationFaultRelayDirectionV1::DesktopToRuntime
    {
        return Err(QualificationAdmissionRelayError);
    }
    Ok(())
}

fn push_frame(bytes: &mut Vec<u8>, frame: &[u8]) -> Result<(), QualificationAdmissionRelayError> {
    let length = u32::try_from(frame.len()).map_err(|_| QualificationAdmissionRelayError)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(frame);
    Ok(())
}

fn read_frame(
    bytes: &[u8],
    offset: usize,
    maximum: usize,
) -> Result<(&[u8], usize), QualificationAdmissionRelayError> {
    let length_end = offset
        .checked_add(OUTER_LENGTH_BYTES)
        .ok_or(QualificationAdmissionRelayError)?;
    let encoded = bytes
        .get(offset..length_end)
        .and_then(|value| value.try_into().ok())
        .ok_or(QualificationAdmissionRelayError)?;
    let length = usize::try_from(u32::from_be_bytes(encoded))
        .map_err(|_| QualificationAdmissionRelayError)?;
    if length == 0 || length > maximum {
        return Err(QualificationAdmissionRelayError);
    }
    let end = length_end
        .checked_add(length)
        .ok_or(QualificationAdmissionRelayError)?;
    let frame = bytes
        .get(length_end..end)
        .ok_or(QualificationAdmissionRelayError)?;
    Ok((frame, end))
}
