use sha2::{Digest as _, Sha256};

use super::super::{
    CredentialBrokerCommandCodec, CredentialBrokerFrame, CredentialBrokerFrameCodec,
};
use crate::credential::enrollment::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialEnrollmentError, CredentialOperationAction,
    CredentialOperationId, CredentialSecretClaimOffer, CredentialTicketAttempt,
    CredentialWriterClaimIssuer, PendingCredentialSecretOpening,
};

#[path = "issue_ticket/scope.rs"]
mod scope;
pub use scope::{
    CredentialSecretInputPresence, CredentialWriterCommandKindV1, CredentialWriterCommandScopeV1,
};

const DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_ISSUE_TICKET_SESSION_V1\0";

#[path = "legacy_read_verifier.rs"]
mod legacy_read_verifier;

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
}

impl PendingCredentialIssueTicketV1 {
    /// Reads and retains exactly one bounded `IssueTicket` frame.
    pub fn read_from<R: std::io::Read>(reader: &mut R) -> Result<Self, CredentialEnrollmentError> {
        let frame = CredentialBrokerFrameCodec::read_from(reader)?;
        let binding = CredentialIssueTicketBindingV1::from_issue_ticket(&frame)?;
        Ok(Self { frame, binding })
    }

    /// Consumes the retained ticket as the sole command source for one claim.
    ///
    /// The control stream must therefore contain only the following
    /// `ClaimAccepted`; a second `IssueTicket` is never read.
    ///
    /// # Errors
    ///
    /// Rejects changed ticket fields, channel substitution, malformed control
    /// frames, or a non-matching acknowledgement before granting authority.
    #[allow(
        clippy::type_complexity,
        reason = "the move-only result deliberately exposes no raw ticket projection"
    )]
    pub fn claim_on<R: std::io::Read + std::io::Write>(
        self,
        control: &mut R,
        issuer: &CredentialWriterClaimIssuer,
        channel: &BrokerChannelBinding,
        secret_input: CredentialSecretInputPresence,
        scope: CredentialWriterCommandScopeV1,
    ) -> Result<
        (
            ClaimedWriterAuthorization,
            CredentialBrokerCommand,
            CredentialBindingDigest,
            CredentialWriterCommandKindV1,
            Option<PendingCredentialSecretOpening>,
        ),
        CredentialEnrollmentError,
    > {
        let Self {
            frame,
            binding: retained_binding,
        } = self;
        let actual_binding = CredentialIssueTicketBindingV1::from_issue_ticket(&frame)?;
        if actual_binding != retained_binding || actual_binding.channel() != channel.digest() {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
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
        if channel_binding != channel.digest().as_bytes() {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let command_kind = scope
            .classify(command.action())
            .ok_or(CredentialEnrollmentError::InvalidEvidence)?;
        let expects_secret = command.action() == CredentialOperationAction::Pair;
        if (secret_input == CredentialSecretInputPresence::Present) != expects_secret {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let pending_claim = issuer.issue_pending_claim(&command, binding, channel);
        let (secret_offer, pending_opening) = if command.action() == CredentialOperationAction::Pair
        {
            let (offer, pending) = CredentialSecretClaimOffer::prepare(&command, binding)?;
            (Some(offer), Some(pending))
        } else {
            (None, None)
        };
        CredentialBrokerFrameCodec::write_to(
            control,
            CredentialBrokerFrame::Claim {
                operation_id,
                attempt,
                ticket,
                binding,
                secret_offer,
            },
        )?;
        let accepted = CredentialBrokerFrameCodec::read_from(control)?;
        let authorization =
            issuer.claim_accepted(pending_claim, accepted, &command, binding, channel)?;
        Ok((
            authorization,
            command,
            binding,
            command_kind,
            pending_opening,
        ))
    }

    pub(super) fn matches_attested(&self, attested: &CredentialIssueTicketBindingV1) -> bool {
        CredentialIssueTicketBindingV1::from_issue_ticket(&self.frame)
            .is_ok_and(|actual| actual == self.binding && &actual == attested)
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
