use std::io::{Read, Write};

use zeroize::Zeroizing;

use super::CredentialBrokerFrame;
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialDisposition, CredentialEnrollmentError,
    CredentialOperationId, CredentialTicketAttempt, RawCredentialTicket,
};

/// Strict versioned codec for the inherited credential broker channel.
pub struct CredentialBrokerFrameCodec;

impl CredentialBrokerFrameCodec {
    /// The only supported broker codec version.
    pub const VERSION: u8 = 1;
    /// Upper bound including version, kind, and all payload fields.
    pub const MAX_FRAME_BYTES: usize = 4 * 1024;

    /// Encodes one known frame in canonical field order.
    pub fn encode(frame: CredentialBrokerFrame) -> Result<Vec<u8>, CredentialEnrollmentError> {
        let mut bytes = vec![Self::VERSION];
        match frame {
            CredentialBrokerFrame::IssueTicket {
                operation_id,
                attempt,
                ticket,
            } => {
                bytes.push(1);
                id(&mut bytes, operation_id);
                encode_attempt(&mut bytes, attempt);
                bytes.extend_from_slice(ticket.bytes());
            }
            CredentialBrokerFrame::Claim {
                operation_id,
                attempt,
                ticket,
                binding,
            } => {
                bytes.push(2);
                id(&mut bytes, operation_id);
                encode_attempt(&mut bytes, attempt);
                bytes.extend_from_slice(ticket.bytes());
                digest(&mut bytes, binding);
            }
            CredentialBrokerFrame::ClaimAccepted {
                operation_id,
                attempt,
            } => {
                bytes.push(3);
                id(&mut bytes, operation_id);
                encode_attempt(&mut bytes, attempt);
            }
            CredentialBrokerFrame::ClaimDenied {
                operation_id,
                attempt,
                disposition,
            } => {
                bytes.push(4);
                id(&mut bytes, operation_id);
                encode_attempt(&mut bytes, attempt);
                bytes.push(disposition as u8);
            }
            CredentialBrokerFrame::NativeEffectObserved {
                operation_id,
                binding,
            } => {
                bytes.push(5);
                id(&mut bytes, operation_id);
                digest(&mut bytes, binding);
            }
        }
        if bytes.len() > Self::MAX_FRAME_BYTES {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Ok(bytes)
    }

    /// Decodes exactly one bounded, known-version frame; all other input fails closed.
    pub fn decode(bytes: &[u8]) -> Result<CredentialBrokerFrame, CredentialEnrollmentError> {
        if bytes.len() < 2 || bytes.len() > Self::MAX_FRAME_BYTES || bytes[0] != Self::VERSION {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let mut cursor = 2;
        let frame = match bytes[1] {
            1 => CredentialBrokerFrame::IssueTicket {
                operation_id: read_id(bytes, &mut cursor)?,
                attempt: read_attempt(bytes, &mut cursor)?,
                ticket: read_ticket(bytes, &mut cursor)?,
            },
            2 => CredentialBrokerFrame::Claim {
                operation_id: read_id(bytes, &mut cursor)?,
                attempt: read_attempt(bytes, &mut cursor)?,
                ticket: read_ticket(bytes, &mut cursor)?,
                binding: read_digest(bytes, &mut cursor)?,
            },
            3 => CredentialBrokerFrame::ClaimAccepted {
                operation_id: read_id(bytes, &mut cursor)?,
                attempt: read_attempt(bytes, &mut cursor)?,
            },
            4 => CredentialBrokerFrame::ClaimDenied {
                operation_id: read_id(bytes, &mut cursor)?,
                attempt: read_attempt(bytes, &mut cursor)?,
                disposition: CredentialDisposition::from_byte(
                    *take(bytes, &mut cursor, 1)?
                        .first()
                        .ok_or(CredentialEnrollmentError::InvalidFrame)?,
                )
                .ok_or(CredentialEnrollmentError::InvalidFrame)?,
            },
            5 => CredentialBrokerFrame::NativeEffectObserved {
                operation_id: read_id(bytes, &mut cursor)?,
                binding: read_digest(bytes, &mut cursor)?,
            },
            _ => return Err(CredentialEnrollmentError::InvalidFrame),
        };
        if cursor != bytes.len() {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Ok(frame)
    }

    /// Reads exactly one canonical frame from an inherited control stream.
    ///
    /// The frame type determines its exact fixed length, so a short frame or a
    /// stream prefix with an unknown kind cannot be interpreted as a different
    /// broker message.
    pub fn read_from(
        reader: &mut impl Read,
    ) -> Result<CredentialBrokerFrame, CredentialEnrollmentError> {
        let mut prefix = [0; 2];
        reader
            .read_exact(&mut prefix)
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        let length = exact_frame_length(prefix)?;
        let mut bytes = Zeroizing::new(vec![0; length]);
        bytes[..2].copy_from_slice(&prefix);
        reader
            .read_exact(&mut bytes[2..])
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        Self::decode(&bytes)
    }

    /// Writes one canonical frame to an inherited control stream and flushes it.
    pub fn write_to(
        writer: &mut impl Write,
        frame: CredentialBrokerFrame,
    ) -> Result<(), CredentialEnrollmentError> {
        let bytes = Zeroizing::new(Self::encode(frame)?);
        writer
            .write_all(&bytes)
            .and_then(|()| writer.flush())
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)
    }
}

fn exact_frame_length(prefix: [u8; 2]) -> Result<usize, CredentialEnrollmentError> {
    if prefix[0] != CredentialBrokerFrameCodec::VERSION {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    match prefix[1] {
        1 => Ok(2 + 16 + 8 + 32),
        2 => Ok(2 + 16 + 8 + 32 + 32),
        3 => Ok(2 + 16 + 8),
        4 => Ok(2 + 16 + 8 + 1),
        5 => Ok(2 + 16 + 32),
        _ => Err(CredentialEnrollmentError::InvalidFrame),
    }
}

fn id(bytes: &mut Vec<u8>, value: CredentialOperationId) {
    bytes.extend_from_slice(&value.as_bytes());
}
fn encode_attempt(bytes: &mut Vec<u8>, value: CredentialTicketAttempt) {
    bytes.extend_from_slice(&value.get().to_be_bytes());
}
fn digest(bytes: &mut Vec<u8>, value: CredentialBindingDigest) {
    bytes.extend_from_slice(&value.as_bytes());
}
fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], CredentialEnrollmentError> {
    let end = cursor
        .checked_add(length)
        .ok_or(CredentialEnrollmentError::InvalidFrame)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(CredentialEnrollmentError::InvalidFrame)?;
    *cursor = end;
    Ok(value)
}
fn read_id(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<CredentialOperationId, CredentialEnrollmentError> {
    CredentialOperationId::from_bytes(
        take(bytes, cursor, 16)?
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    )
}
fn read_attempt(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<CredentialTicketAttempt, CredentialEnrollmentError> {
    CredentialTicketAttempt::new(u64::from_be_bytes(
        take(bytes, cursor, 8)?
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    ))
}
fn read_digest(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<CredentialBindingDigest, CredentialEnrollmentError> {
    CredentialBindingDigest::from_measured(
        take(bytes, cursor, 32)?
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    )
}
fn read_ticket(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<RawCredentialTicket, CredentialEnrollmentError> {
    RawCredentialTicket::from_decoded(
        take(bytes, cursor, 32)?
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    )
}
