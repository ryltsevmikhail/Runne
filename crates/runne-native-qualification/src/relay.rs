use std::fmt;

use runne_api::{
    ProtectedActivationKeys, QualificationFaultRelayAuthenticator,
    QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
    QualificationFaultRelayTicketBindingV1,
};
use sha2::{Digest as _, Sha256};

use crate::{MAX_FAULT_TICKET_BYTES, PendingQualificationFault};

const MAGIC: &[u8; 8] = b"RNQFRLY1";
const VERSION: u8 = 1;
const FIXED_PREFIX_BYTES: usize = 79;
const MAC_BYTES: usize = 32;

/// Closed relay-frame rejection without ticket or binding detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationFaultRelayError;

impl fmt::Display for QualificationFaultRelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification fault relay rejected")
    }
}

impl std::error::Error for QualificationFaultRelayError {}

/// Version-1 bounded codec authenticated by one protected activation.
pub struct QualificationFaultRelayCodecV1 {
    authenticator: QualificationFaultRelayAuthenticator,
}

impl QualificationFaultRelayCodecV1 {
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            authenticator: QualificationFaultRelayAuthenticator::from_protected_activation(keys),
        }
    }

    /// Routing hint for one length-prefixed protected-channel frame.
    /// Authentication and exact binding checks remain mandatory after this hint.
    #[must_use]
    pub fn recognizes_frame(frame: &[u8]) -> bool {
        frame.get(4..12) == Some(MAGIC.as_slice())
    }

    /// Encodes an explicit canonical absence.
    ///
    /// # Errors
    ///
    /// Returns a closed rejection if the binding cannot be encoded exactly.
    pub fn encode_none(
        &self,
        binding: &QualificationFaultRelayBindingV1,
    ) -> Result<Vec<u8>, QualificationFaultRelayError> {
        self.encode(binding, None)
    }

    pub(crate) fn encode_ticket(
        &self,
        binding: &QualificationFaultRelayBindingV1,
        ticket: &[u8],
    ) -> Result<Vec<u8>, QualificationFaultRelayError> {
        if ticket.is_empty() || ticket.len() > MAX_FAULT_TICKET_BYTES {
            return Err(QualificationFaultRelayError);
        }
        self.encode(binding, Some(ticket))
    }

    fn encode(
        &self,
        binding: &QualificationFaultRelayBindingV1,
        ticket: Option<&[u8]>,
    ) -> Result<Vec<u8>, QualificationFaultRelayError> {
        let ticket_binding = ticket_binding(ticket)?;
        let length = ticket.map_or(0, <[u8]>::len);
        let mut frame = Vec::with_capacity(FIXED_PREFIX_BYTES + length + MAC_BYTES);
        frame.extend_from_slice(MAGIC);
        frame.push(VERSION);
        frame.push(binding.direction().wire_tag());
        frame.extend_from_slice(&binding.protected_session_id());
        frame.extend_from_slice(&binding.release_tuple_v3_sha256());
        frame.extend_from_slice(&binding.launch_generation().to_be_bytes());
        frame.extend_from_slice(&binding.sequence().to_be_bytes());
        frame.push(u8::from(ticket.is_some()));
        frame.extend_from_slice(
            &u32::try_from(length)
                .map_err(|_| QualificationFaultRelayError)?
                .to_be_bytes(),
        );
        if let Some(bytes) = ticket {
            frame.extend_from_slice(bytes);
        }
        frame.extend_from_slice(&self.authenticator.authenticate(binding, &ticket_binding));
        Ok(frame)
    }

    /// Decodes only a frame matching the exact independently supplied binding.
    ///
    /// # Errors
    ///
    /// Returns a closed rejection for any authentication, context, version,
    /// direction, length, bound, canonical-ticket, or framing mismatch.
    pub fn decode(
        &self,
        frame: &[u8],
        expected: &QualificationFaultRelayBindingV1,
    ) -> Result<Option<PendingQualificationFault>, QualificationFaultRelayError> {
        if frame.len() < FIXED_PREFIX_BYTES + MAC_BYTES
            || &frame[..8] != MAGIC
            || frame[8] != VERSION
        {
            return Err(QualificationFaultRelayError);
        }
        let direction = QualificationFaultRelayDirectionV1::from_wire_tag(frame[9])
            .ok_or(QualificationFaultRelayError)?;
        let observed = QualificationFaultRelayBindingV1::new(
            take::<16>(frame, 10)?,
            take::<32>(frame, 26)?,
            u64::from_be_bytes(take::<8>(frame, 58)?),
            direction,
            u64::from_be_bytes(take::<8>(frame, 66)?),
        )
        .map_err(|_| QualificationFaultRelayError)?;
        if &observed != expected {
            return Err(QualificationFaultRelayError);
        }
        let presence = frame[74];
        let length = usize::try_from(u32::from_be_bytes(take::<4>(frame, 75)?))
            .map_err(|_| QualificationFaultRelayError)?;
        if !matches!((presence, length), (0, 0) | (1, 1..=MAX_FAULT_TICKET_BYTES))
            || frame.len() != FIXED_PREFIX_BYTES + length + MAC_BYTES
        {
            return Err(QualificationFaultRelayError);
        }
        let ticket = (presence == 1).then_some(&frame[FIXED_PREFIX_BYTES..][..length]);
        let ticket_binding = ticket_binding(ticket)?;
        let proof = take::<32>(frame, FIXED_PREFIX_BYTES + length)?;
        if !self
            .authenticator
            .verifies(&observed, &ticket_binding, &proof)
        {
            return Err(QualificationFaultRelayError);
        }
        ticket
            .map(|bytes| PendingQualificationFault::from_admitted_frame(bytes.to_vec()))
            .transpose()
            .map_err(|_| QualificationFaultRelayError)
    }
}

fn ticket_binding(
    ticket: Option<&[u8]>,
) -> Result<QualificationFaultRelayTicketBindingV1, QualificationFaultRelayError> {
    match ticket {
        None => Ok(QualificationFaultRelayTicketBindingV1::none()),
        Some(bytes) => QualificationFaultRelayTicketBindingV1::present(
            u32::try_from(bytes.len()).map_err(|_| QualificationFaultRelayError)?,
            Sha256::digest(bytes).into(),
        )
        .map_err(|_| QualificationFaultRelayError),
    }
}

fn take<const N: usize>(
    frame: &[u8],
    offset: usize,
) -> Result<[u8; N], QualificationFaultRelayError> {
    frame
        .get(offset..offset + N)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(QualificationFaultRelayError)
}
