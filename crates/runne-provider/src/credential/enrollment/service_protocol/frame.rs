use std::io::Read;

use crate::credential::enrollment::CredentialEnrollmentError;
use zeroize::Zeroizing;

/// Move-only zeroizing canonical credential-service request frame.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_provider::CredentialServiceRequestFrame>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_provider::CredentialServiceRequestFrame>();
/// ```
pub struct CredentialServiceRequestFrame(pub(super) Zeroizing<Vec<u8>>);

/// Move-only zeroizing context-bound credential-service reply frame.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_provider::CredentialServiceReplyFrame>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_provider::CredentialServiceReplyFrame>();
/// ```
pub struct CredentialServiceReplyFrame(pub(super) Zeroizing<Vec<u8>>);

/// Move-only zeroizing runtime-to-writer broker handoff frame.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_provider::CredentialWriterBrokerHandoffFrame>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_provider::CredentialWriterBrokerHandoffFrame>();
/// ```
pub struct CredentialWriterBrokerHandoffFrame(pub(super) Zeroizing<Vec<u8>>);

macro_rules! frame_api {
    ($name:ident) => {
        impl $name {
            /// Consumes bytes only at the authenticated service transport boundary.
            pub fn send<E>(self, send: impl FnOnce(&[u8]) -> Result<(), E>) -> Result<(), E> {
                send(&self.0)
            }

            /// Moves the canonical allocation into the native transport frame.
            #[must_use]
            pub fn into_transport_bytes(self) -> Zeroizing<Vec<u8>> {
                self.0
            }

            #[cfg(test)]
            pub(crate) fn test_bytes(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

frame_api!(CredentialServiceRequestFrame);
frame_api!(CredentialServiceReplyFrame);
frame_api!(CredentialWriterBrokerHandoffFrame);

impl CredentialWriterBrokerHandoffFrame {
    /// Reads exactly one canonical bounded handoff frame from a live broker stream.
    pub fn read_from(reader: &mut impl Read) -> Result<Self, CredentialEnrollmentError> {
        const HEADER_BYTES: usize = 14;
        let mut header = [0_u8; HEADER_BYTES];
        reader
            .read_exact(&mut header)
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        if header[..8] != super::CredentialServiceProtocolCodec::MAGIC
            || header[8..10] != super::CredentialServiceProtocolCodec::VERSION.to_be_bytes()
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let payload_len = usize::try_from(u32::from_be_bytes(
            header[10..14]
                .try_into()
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
        ))
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        let frame_len = HEADER_BYTES
            .checked_add(payload_len)
            .ok_or(CredentialEnrollmentError::InvalidFrame)?;
        if payload_len == 0 || frame_len > super::CredentialServiceProtocolCodec::MAX_FRAME_BYTES {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(frame_len));
        bytes.extend_from_slice(&header);
        bytes.resize(frame_len, 0);
        reader
            .read_exact(&mut bytes[HEADER_BYTES..])
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        Ok(Self(bytes))
    }
}
