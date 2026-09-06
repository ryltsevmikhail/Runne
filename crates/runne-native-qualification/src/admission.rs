use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::{MAX_ADMISSION_BUNDLE_BYTES, PendingQualificationFault};

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

struct PendingQualificationRunContext {
    _bytes: Vec<u8>,
}

/// Opaque context-plus-ticket pair retained after bounded semantic admission.
pub struct PendingQualificationAdmission {
    _context: PendingQualificationRunContext,
    _fault: PendingQualificationFault,
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
            _context: PendingQualificationRunContext {
                _bytes: context_bytes,
            },
            _fault: fault,
        })
    }
}

fn read_len(bytes: &[u8], offset: usize) -> Result<usize, QualificationAdmissionError> {
    let encoded: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .ok_or(QualificationAdmissionError)?;
    usize::try_from(u32::from_be_bytes(encoded)).map_err(|_| QualificationAdmissionError)
}
