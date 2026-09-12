use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::{
    MAX_ADMISSION_BUNDLE_BYTES, PendingQualificationFault, PendingQualificationRunContext,
    QualificationAdmissionRelayCodecV1, QualificationAdmissionRelayError,
    QualificationAdmissionRelayTranscript,
};

const MAGIC: &[u8; 8] = b"RNQADM1\0";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 17;

/// Closed rejection for a malformed or internally inconsistent admission pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAdmissionError;

impl fmt::Display for QualificationAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification admission bundle rejected")
    }
}

impl std::error::Error for QualificationAdmissionError {}

/// Opaque context-plus-ticket pair retained after bounded semantic admission.
pub struct PendingQualificationAdmission {
    context: PendingQualificationRunContext,
    fault: PendingQualificationFault,
}

impl PendingQualificationAdmission {
    /// Admits one exact version-1 context-plus-unchanged-ticket bundle.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds, framing, canonical member shape, ticket digest,
    /// context/ticket expiry order, or any trailing/truncated input.
    pub fn from_admitted_bundle(bytes: Vec<u8>) -> Result<Self, QualificationAdmissionError> {
        if bytes.len() < HEADER_BYTES + 2 || bytes.len() > MAX_ADMISSION_BUNDLE_BYTES {
            return Err(QualificationAdmissionError);
        }
        if bytes.get(..8) != Some(MAGIC.as_slice()) || bytes[8] != VERSION {
            return Err(QualificationAdmissionError);
        }
        let context_len = read_len(&bytes, 9)?;
        let ticket_len = read_len(&bytes, 13)?;
        if !(1..=crate::MAX_RUN_CONTEXT_BYTES).contains(&context_len)
            || !(1..=crate::MAX_FAULT_TICKET_BYTES).contains(&ticket_len)
        {
            return Err(QualificationAdmissionError);
        }
        let context_end = HEADER_BYTES
            .checked_add(context_len)
            .ok_or(QualificationAdmissionError)?;
        let expected_end = context_end
            .checked_add(ticket_len)
            .ok_or(QualificationAdmissionError)?;
        if expected_end != bytes.len() {
            return Err(QualificationAdmissionError);
        }
        let mut bytes = bytes;
        let ticket_bytes = bytes.split_off(context_end);
        let context_bytes = bytes.split_off(HEADER_BYTES);
        let context =
            crate::context_wire::decode(&context_bytes).map_err(|_| QualificationAdmissionError)?;
        let context_shape = crate::context_verification::validate_admitted_shape(
            &context,
            crate::QualificationRunContextError::InvalidContext,
        )
        .map_err(|_| QualificationAdmissionError)?;
        let ticket = crate::wire::decode(&ticket_bytes).map_err(|_| QualificationAdmissionError)?;
        crate::verification::validate_admitted_shape(
            &ticket,
            crate::QualificationFaultError::InvalidTicket,
        )
        .map_err(|_| QualificationAdmissionError)?;
        if context_shape.ticket_sha256 != Sha256::digest(&ticket_bytes).as_slice()
            || context.expires_at > ticket.expires_at
        {
            return Err(QualificationAdmissionError);
        }
        let fault = PendingQualificationFault::from_admitted_frame(ticket_bytes)
            .map_err(|_| QualificationAdmissionError)?;
        Ok(Self {
            context: PendingQualificationRunContext::from_admitted_frame(context_bytes)
                .map_err(|_| QualificationAdmissionError)?,
            fault,
        })
    }

    /// Consumes the admitted pair into one exact context-first transcript.
    ///
    /// # Errors
    ///
    /// Rejects mismatched protected sessions, release tuples, generations,
    /// non-Desktop fault direction, or either closed relay encoding failure.
    pub fn encode_relay_transcript(
        self,
        codec: &QualificationAdmissionRelayCodecV1,
        context_binding: &runne_api::QualificationRunContextRelayBindingV1,
        fault_binding: &runne_api::QualificationFaultRelayBindingV1,
    ) -> Result<QualificationAdmissionRelayTranscript, QualificationAdmissionRelayError> {
        codec.encode(self.context, self.fault, context_binding, fault_binding)
    }

    pub(crate) fn from_relay_members(
        context: PendingQualificationRunContext,
        fault: PendingQualificationFault,
    ) -> Result<Self, QualificationAdmissionRelayError> {
        if !context.matches_fault(&fault) {
            return Err(QualificationAdmissionRelayError);
        }
        Ok(Self { context, fault })
    }

    pub(crate) fn verify_and_consume_borrowed(
        &self,
        context_verifier: &mut crate::QualificationRunContextVerifier,
        fault_verifier: &mut crate::QualificationFaultVerifier,
        expected: &crate::QualificationRunContextExpectation,
        now_unix_seconds: u64,
    ) -> Result<
        crate::VerifiedQualificationFenceFacts,
        crate::QualificationAdmissionVerificationError,
    > {
        let context = self
            .context
            .verify_expected_borrowed(context_verifier, expected, now_unix_seconds)
            .map_err(|_| crate::QualificationAdmissionVerificationError)?;
        let binding = expected
            .fault_context()
            .map_err(|_| crate::QualificationAdmissionVerificationError)?;
        let fault = self
            .fault
            .verify_borrowed(fault_verifier, &binding, now_unix_seconds)
            .map_err(|_| crate::QualificationAdmissionVerificationError)?;
        Ok(crate::VerifiedQualificationFenceFacts::verified(
            context, fault, binding,
        ))
    }

    pub(crate) fn verify_exact_borrowed(
        &self,
        context_verifier: &mut crate::QualificationRunContextVerifier,
        fault_verifier: &mut crate::QualificationFaultVerifier,
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<(), crate::QualificationAdmissionVerificationError> {
        let _ = self.verify_exact_fault_borrowed(
            context_verifier,
            fault_verifier,
            candidate_sha256,
            raw_v3_tuple_sha256,
            now_unix_seconds,
        )?;
        Ok(())
    }

    pub(crate) fn verify_exact_for_fence_borrowed(
        &self,
        context_verifier: &mut crate::QualificationRunContextVerifier,
        fault_verifier: &mut crate::QualificationFaultVerifier,
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<
        crate::VerifiedQualificationFenceFacts,
        crate::QualificationAdmissionVerificationError,
    > {
        let (context, binding) = self
            .context
            .verify_installed_borrowed(
                context_verifier,
                candidate_sha256,
                raw_v3_tuple_sha256,
                now_unix_seconds,
            )
            .map_err(|_| crate::QualificationAdmissionVerificationError)?;
        let fault = self
            .fault
            .verify_borrowed(fault_verifier, &binding, now_unix_seconds)
            .map_err(|_| crate::QualificationAdmissionVerificationError)?;
        Ok(crate::VerifiedQualificationFenceFacts::verified(
            context, fault, binding,
        ))
    }

    pub(crate) fn verify_exact_writer_fault_borrowed(
        &self,
        context_verifier: &mut crate::QualificationRunContextVerifier,
        fault_verifier: &mut crate::QualificationFaultVerifier,
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<crate::VerifiedQualificationFault, crate::QualificationAdmissionVerificationError>
    {
        let (binding, fault) = self.verify_exact_fault_borrowed(
            context_verifier,
            fault_verifier,
            candidate_sha256,
            raw_v3_tuple_sha256,
            now_unix_seconds,
        )?;
        if binding.process_role != crate::QualificationProcessRole::Writer
            || binding.selector != crate::QualificationFaultSelector::WriterProcess
        {
            return Err(crate::QualificationAdmissionVerificationError);
        }
        Ok(fault)
    }

    pub(crate) fn verify_exact_service_fault_borrowed(
        &self,
        context_verifier: &mut crate::QualificationRunContextVerifier,
        fault_verifier: &mut crate::QualificationFaultVerifier,
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<crate::VerifiedQualificationFault, crate::QualificationAdmissionVerificationError>
    {
        let (binding, fault) = self.verify_exact_fault_borrowed(
            context_verifier,
            fault_verifier,
            candidate_sha256,
            raw_v3_tuple_sha256,
            now_unix_seconds,
        )?;
        if binding.process_role != crate::QualificationProcessRole::Service
            || binding.selector.process_role() != crate::QualificationProcessRole::Service
        {
            return Err(crate::QualificationAdmissionVerificationError);
        }
        Ok(fault)
    }

    /// Independently verifies the pair before a local role-specific transition.
    fn verify_exact_fault_borrowed(
        &self,
        context_verifier: &mut crate::QualificationRunContextVerifier,
        fault_verifier: &mut crate::QualificationFaultVerifier,
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<
        (
            crate::QualificationFaultContext,
            crate::VerifiedQualificationFault,
        ),
        crate::QualificationAdmissionVerificationError,
    > {
        let (_context, binding) = self
            .context
            .verify_installed_borrowed(
                context_verifier,
                candidate_sha256,
                raw_v3_tuple_sha256,
                now_unix_seconds,
            )
            .map_err(|_| crate::QualificationAdmissionVerificationError)?;
        let fault = self
            .fault
            .verify_borrowed(fault_verifier, &binding, now_unix_seconds)
            .map_err(|_| crate::QualificationAdmissionVerificationError)?;
        Ok((binding, fault))
    }
}

fn read_len(bytes: &[u8], offset: usize) -> Result<usize, QualificationAdmissionError> {
    let encoded: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .ok_or(QualificationAdmissionError)?;
    usize::try_from(u32::from_be_bytes(encoded)).map_err(|_| QualificationAdmissionError)
}
