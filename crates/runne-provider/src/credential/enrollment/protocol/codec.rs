use super::{
    CredentialBrokerCommand, CredentialBrokerCommandCodec, CredentialBrokerFrame,
    CredentialSecretOfferCodec,
};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialDisposition, CredentialEnrollmentError,
    CredentialOperationId, CredentialTicketAttempt, RawCredentialTicket,
};

/// Strict versioned codec for the inherited credential broker channel.
pub struct CredentialBrokerFrameCodec;

mod stream;
mod validation;
use validation::valid_frame;

impl CredentialBrokerFrameCodec {
    /// The only supported broker codec version.
    pub const VERSION: u8 = 5;
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
                channel_binding,
                binding,
                command,
            } => {
                if command.operation_id() != operation_id || command.ticket_attempt() != attempt {
                    return Err(CredentialEnrollmentError::InvalidFrame);
                }
                bytes.push(1);
                id(&mut bytes, operation_id);
                encode_attempt(&mut bytes, attempt);
                bytes.extend_from_slice(ticket.bytes());
                bytes.extend_from_slice(&channel_binding);
                digest(&mut bytes, binding);
                encode_command(&mut bytes, command)?;
            }
            CredentialBrokerFrame::Claim {
                operation_id,
                attempt,
                ticket,
                binding,
                secret_offer,
            } => {
                bytes.push(2);
                id(&mut bytes, operation_id);
                encode_attempt(&mut bytes, attempt);
                bytes.extend_from_slice(ticket.bytes());
                digest(&mut bytes, binding);
                let slot = match secret_offer {
                    Some(offer)
                        if offer.operation_id == operation_id
                            && offer.attempt == attempt
                            && offer.claim_binding == binding =>
                    {
                        bytes.push(1);
                        CredentialSecretOfferCodec::encode(&offer)
                    }
                    Some(_) => return Err(CredentialEnrollmentError::InvalidFrame),
                    None => {
                        bytes.push(0);
                        [0; CredentialSecretOfferCodec::BYTES]
                    }
                };
                bytes.extend_from_slice(&slot);
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
            CredentialBrokerFrame::NativeEffectRelease {
                operation_id,
                attempt,
                binding,
            } => {
                bytes.push(6);
                id(&mut bytes, operation_id);
                encode_attempt(&mut bytes, attempt);
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
                channel_binding: read_bytes(bytes, &mut cursor)?,
                binding: read_digest(bytes, &mut cursor)?,
                command: read_command(bytes, &mut cursor)?,
            },
            2 => CredentialBrokerFrame::Claim {
                operation_id: read_id(bytes, &mut cursor)?,
                attempt: read_attempt(bytes, &mut cursor)?,
                ticket: read_ticket(bytes, &mut cursor)?,
                binding: read_digest(bytes, &mut cursor)?,
                secret_offer: read_secret_offer(bytes, &mut cursor)?,
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
            6 => CredentialBrokerFrame::NativeEffectRelease {
                operation_id: read_id(bytes, &mut cursor)?,
                attempt: read_attempt(bytes, &mut cursor)?,
                binding: read_digest(bytes, &mut cursor)?,
            },
            _ => return Err(CredentialEnrollmentError::InvalidFrame),
        };
        if cursor != bytes.len() || !valid_frame(&frame) {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Ok(frame)
    }

    /// Reads one exact canonical frame from an inherited control stream.
    pub fn read_from(
        reader: &mut impl std::io::Read,
    ) -> Result<CredentialBrokerFrame, CredentialEnrollmentError> {
        stream::read_from(reader)
    }

    /// Writes one canonical frame and flushes the inherited control stream.
    pub fn write_to(
        writer: &mut impl std::io::Write,
        frame: CredentialBrokerFrame,
    ) -> Result<(), CredentialEnrollmentError> {
        stream::write_to(writer, frame)
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
fn read_bytes(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 32], CredentialEnrollmentError> {
    take(bytes, cursor, 32)?
        .try_into()
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
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
fn read_secret_offer(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Option<super::CredentialSecretClaimOffer>, CredentialEnrollmentError> {
    let flag = *take(bytes, cursor, 1)?
        .first()
        .ok_or(CredentialEnrollmentError::InvalidFrame)?;
    let slot = take(bytes, cursor, CredentialSecretOfferCodec::BYTES)?;
    match flag {
        0 if slot.iter().all(|byte| *byte == 0) => Ok(None),
        1 => CredentialSecretOfferCodec::decode(slot).map(Some),
        _ => Err(CredentialEnrollmentError::InvalidFrame),
    }
}
fn encode_command(
    bytes: &mut Vec<u8>,
    command: CredentialBrokerCommand,
) -> Result<(), CredentialEnrollmentError> {
    let command = CredentialBrokerCommandCodec::encode(&command)?;
    let length =
        u16::try_from(command.len()).map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&command);
    Ok(())
}
fn read_command(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<CredentialBrokerCommand, CredentialEnrollmentError> {
    let length = usize::from(u16::from_be_bytes(
        take(bytes, cursor, 2)?
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    ));
    if length == 0 || length > CredentialBrokerCommandCodec::MAX_COMMAND_BYTES {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    CredentialBrokerCommandCodec::decode(take(bytes, cursor, length)?)
}
