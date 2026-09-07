use sha2::{Digest as _, Sha256};

use super::super::{
    CredentialBrokerCommandCodec, CredentialBrokerFrame, CredentialBrokerFrameCodec,
};
use super::qualified::WriterQualificationReceiver;
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationId,
    CredentialTicketAttempt,
};

#[path = "issue_ticket/claim.rs"]
mod claim;
#[path = "issue_ticket/scope.rs"]
mod scope;
pub use scope::{
    CredentialSecretInputPresence, CredentialWriterCommandKindV1, CredentialWriterCommandScopeV1,
};

const DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_ISSUE_TICKET_SESSION_V1\0";

#[path = "legacy_read_verifier.rs"]
mod legacy_read_verifier;
#[path = "issue_ticket/qualified.rs"]
mod qualified;

/// One prefetched broker ticket retained for a later authenticated claim.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_provider::PendingCredentialIssueTicketV1>();
/// ```
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<runne_provider::PendingCredentialIssueTicketV1>();
/// ```
/// ```compile_fail
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<runne_provider::PendingCredentialIssueTicketV1>();
/// ```
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<runne_provider::PendingCredentialIssueTicketV1>();
/// ```
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_provider::PendingCredentialIssueTicketV1>();
/// ```
/// ```compile_fail
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<runne_provider::PendingCredentialIssueTicketV1>();
/// ```
/// ```compile_fail
/// fn require_as_fd<T: std::os::fd::AsFd>() {}
/// require_as_fd::<runne_provider::PendingCredentialIssueTicketV1>();
/// ```
/// ```compile_fail
/// fn require_as_raw_fd<T: std::os::fd::AsRawFd>() {}
/// require_as_raw_fd::<runne_provider::PendingCredentialIssueTicketV1>();
/// ```
/// ```compile_fail
/// fn require_into_raw_fd<T: std::os::fd::IntoRawFd>() {}
/// require_into_raw_fd::<runne_provider::PendingCredentialIssueTicketV1>();
/// ```
/// ```compile_fail
/// let _ = runne_provider::PendingCredentialIssueTicketV1 {};
/// ```
/// ```compile_fail
/// let _ = runne_provider::PendingCredentialIssueTicketV1::from_parts();
/// ```
/// ```compile_fail
/// fn pending_has_no_raw_projection(value: runne_provider::PendingCredentialIssueTicketV1) {
///     let _ = value.frame();
///     let _ = value.binding();
///     let _ = value.into_frame();
/// }
/// ```
pub struct PendingCredentialIssueTicketV1 {
    frame: CredentialBrokerFrame,
    binding: CredentialIssueTicketBindingV1,
    qualified_receiver: Option<WriterQualificationReceiver>,
}

impl PendingCredentialIssueTicketV1 {
    /// Reads and retains exactly one bounded `IssueTicket` frame.
    pub fn read_from<R: std::io::Read>(reader: &mut R) -> Result<Self, CredentialEnrollmentError> {
        let frame = CredentialBrokerFrameCodec::read_from(reader)?;
        let binding = CredentialIssueTicketBindingV1::from_issue_ticket(&frame)?;
        Ok(Self {
            frame,
            binding,
            qualified_receiver: None,
        })
    }

    pub(super) fn matches_attested(&self, attested: &CredentialIssueTicketBindingV1) -> bool {
        CredentialIssueTicketBindingV1::from_issue_ticket(&self.frame)
            .is_ok_and(|actual| actual == self.binding && &actual == attested)
    }

    pub(super) fn take_qualified_receiver(&mut self) -> Option<WriterQualificationReceiver> {
        self.qualified_receiver.take()
    }

    pub(super) fn retain_qualified_receiver(&mut self, receiver: WriterQualificationReceiver) {
        self.qualified_receiver = Some(receiver);
    }
}

/// Digest of one actual structured `IssueTicket`; raw ticket bytes never escape.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_provider::CredentialIssueTicketBindingV1>();
/// ```
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<runne_provider::CredentialIssueTicketBindingV1>();
/// ```
/// ```compile_fail
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<runne_provider::CredentialIssueTicketBindingV1>();
/// ```
/// ```compile_fail
/// fn raw_binding_getter(value: &runne_provider::CredentialIssueTicketBindingV1) {
///     let _ = value.digest();
/// }
/// ```
#[derive(Eq, PartialEq)]
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

    pub(super) const fn digest(&self) -> CredentialBindingDigest {
        self.digest
    }

    #[cfg(test)]
    pub(crate) const fn test_only_digest(&self) -> CredentialBindingDigest {
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
        &self,
        operation: CredentialOperationId,
        attempt: CredentialTicketAttempt,
        claim: CredentialBindingDigest,
    ) -> bool {
        self.operation == operation && self.attempt == attempt && self.claim == claim
    }

    pub(super) const fn channel(&self) -> CredentialBindingDigest {
        self.channel
    }
}
