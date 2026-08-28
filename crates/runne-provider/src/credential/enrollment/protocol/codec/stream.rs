use std::io::{Read, Write};

use zeroize::Zeroizing;

use super::super::CredentialSecretOfferCodec;
use super::{CredentialBrokerFrame, CredentialBrokerFrameCodec};
use crate::credential::enrollment::{CredentialBrokerCommandCodec, CredentialEnrollmentError};

pub(super) fn read_from(
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
    if prefix[1] == 1 {
        let command_length = usize::from(u16::from_be_bytes(
            bytes[length - 2..]
                .try_into()
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
        ));
        if command_length == 0
            || command_length > CredentialBrokerCommandCodec::MAX_COMMAND_BYTES
            || length
                .checked_add(command_length)
                .ok_or(CredentialEnrollmentError::InvalidFrame)?
                > CredentialBrokerFrameCodec::MAX_FRAME_BYTES
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        bytes.resize(length + command_length, 0);
        reader
            .read_exact(&mut bytes[length..])
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    }
    CredentialBrokerFrameCodec::decode(&bytes)
}

pub(super) fn write_to(
    writer: &mut impl Write,
    frame: CredentialBrokerFrame,
) -> Result<(), CredentialEnrollmentError> {
    let bytes = Zeroizing::new(CredentialBrokerFrameCodec::encode(frame)?);
    writer
        .write_all(&bytes)
        .and_then(|()| writer.flush())
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}

fn exact_frame_length(prefix: [u8; 2]) -> Result<usize, CredentialEnrollmentError> {
    if prefix[0] != CredentialBrokerFrameCodec::VERSION {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    match prefix[1] {
        1 => Ok(2 + 16 + 8 + 32 + 32 + 32 + 2),
        2 => Ok(2 + 16 + 8 + 32 + 32 + 1 + CredentialSecretOfferCodec::BYTES),
        3 => Ok(2 + 16 + 8),
        4 => Ok(2 + 16 + 8 + 1),
        5 => Ok(2 + 16 + 32),
        _ => Err(CredentialEnrollmentError::InvalidFrame),
    }
}
