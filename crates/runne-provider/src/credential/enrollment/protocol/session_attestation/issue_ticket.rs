use sha2::{Digest as _, Sha256};

use super::super::{
    CredentialBrokerCommandCodec, CredentialBrokerFrame, CredentialBrokerFrameCodec,
};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationId,
    CredentialTicketAttempt,
};

const DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_ISSUE_TICKET_SESSION_V1\0";

/// Digest of one actual structured `IssueTicket`; raw ticket bytes never escape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialIssueTicketBindingV1 {
    digest: CredentialBindingDigest,
    operation: CredentialOperationId,
    attempt: CredentialTicketAttempt,
    claim: CredentialBindingDigest,
    channel: CredentialBindingDigest,
}

impl CredentialIssueTicketBindingV1 {
    /// Computes the exact binding directly from a validated opaque frame.
    pub fn from_issue_ticket(
        frame: &CredentialBrokerFrame,
    ) -> Result<Self, CredentialEnrollmentError> {
        let CredentialBrokerFrame::IssueTicket {
            operation_id,
            attempt,
            ticket,
            channel_binding,
            binding,
            command,
        } = frame
        else {
            return Err(CredentialEnrollmentError::InvalidFrame);
        };
        if command.operation_id() != *operation_id
            || command.ticket_attempt() != *attempt
            || *channel_binding == [0; 32]
            || binding.as_bytes() == [0; 32]
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let command = CredentialBrokerCommandCodec::encode(command)?;
        let command_length =
            u32::try_from(command.len()).map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        let ticket_digest: [u8; 32] = Sha256::digest(ticket.bytes()).into();
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update([CredentialBrokerFrameCodec::VERSION]);
        hasher.update(operation_id.as_bytes());
        hasher.update(attempt.get().to_be_bytes());
        hasher.update(ticket_digest);
        hasher.update(channel_binding);
        hasher.update(binding.as_bytes());
        hasher.update(command_length.to_be_bytes());
        hasher.update(command);
        Ok(Self {
            digest: CredentialBindingDigest::from_measured(hasher.finalize().into())?,
            operation: *operation_id,
            attempt: *attempt,
            claim: *binding,
            channel: CredentialBindingDigest::from_measured(*channel_binding)
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
        })
    }

    /// Returns only the non-secret binding digest.
    #[must_use]
    pub const fn digest(self) -> CredentialBindingDigest {
        self.digest
    }

    pub(super) fn from_attested_digest(
        digest: [u8; 32],
        operation: CredentialOperationId,
        attempt: CredentialTicketAttempt,
        claim: CredentialBindingDigest,
        channel: CredentialBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        CredentialBindingDigest::from_measured(digest)
            .map(|digest| Self {
                digest,
                operation,
                attempt,
                claim,
                channel,
            })
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)
    }

    pub(super) fn matches_claims(
        self,
        operation: CredentialOperationId,
        attempt: CredentialTicketAttempt,
        claim: CredentialBindingDigest,
    ) -> bool {
        self.operation == operation && self.attempt == attempt && self.claim == claim
    }

    pub(super) const fn channel(self) -> CredentialBindingDigest {
        self.channel
    }
}
