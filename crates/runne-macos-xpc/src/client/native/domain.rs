use objc2::rc::Retained;
use objc2_foundation::{NSData, NSXPCInterface};
use zeroize::Zeroizing;

use crate::CredentialServiceXpcError;
use crate::frame::{NativeReplyFrame, NativeRequestFrame, native as credential};

#[derive(Clone, Copy)]
pub(super) enum NativeXpcDomain {
    Credential,
    Qualification,
}

impl NativeXpcDomain {
    pub(super) fn interface(self) -> Retained<NSXPCInterface> {
        match self {
            Self::Credential => credential::interface(),
            Self::Qualification => crate::qualification_runner_native::interface(),
        }
    }

    pub(super) fn prepare_request(
        self,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
        match self {
            Self::Credential => NativeRequestFrame::new(bytes).map(NativeRequestFrame::into_bytes),
            Self::Qualification => Ok(bytes),
        }
    }

    pub(super) fn request_data(self, bytes: &[u8]) -> Retained<NSData> {
        match self {
            Self::Credential => credential_request_data(bytes),
            Self::Qualification => crate::qualification_runner_native::request_data(bytes),
        }
    }

    pub(super) fn copy_reply(
        self,
        data: &NSData,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
        match self {
            Self::Credential => credential_copy_reply(data),
            Self::Qualification => crate::qualification_runner_native::copy_reply(data)
                .map_err(|error| self.reply_error(error)),
        }
    }

    const fn reply_error(self, error: CredentialServiceXpcError) -> CredentialServiceXpcError {
        match self {
            Self::Credential => error,
            Self::Qualification => CredentialServiceXpcError::OutcomeUnknown,
        }
    }
}

fn credential_request_data(bytes: &[u8]) -> Retained<NSData> {
    let frame = NativeRequestFrame::new(Zeroizing::new(bytes.to_vec()))
        .expect("credential request was validated before native dispatch");
    credential::request_data(&frame)
}

fn credential_copy_reply(data: &NSData) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
    credential::copy_reply(data).map(NativeReplyFrame::into_bytes)
}

#[cfg(test)]
mod tests {
    use super::NativeXpcDomain;
    use crate::CredentialServiceXpcError;

    #[test]
    fn credential_malformed_reply_stays_invalid_reply() {
        assert_eq!(
            NativeXpcDomain::Credential.reply_error(CredentialServiceXpcError::InvalidReply),
            CredentialServiceXpcError::InvalidReply
        );
    }

    #[test]
    fn qualification_malformed_ack_is_outcome_unknown() {
        assert_eq!(
            NativeXpcDomain::Qualification.reply_error(CredentialServiceXpcError::InvalidReply),
            CredentialServiceXpcError::OutcomeUnknown
        );
    }
}
