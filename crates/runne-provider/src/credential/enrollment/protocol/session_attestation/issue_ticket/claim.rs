use super::scope::{CredentialWriterCommandKindV1, CredentialWriterCommandScopeV1};
use super::{
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialIssueTicketBindingV1,
    PendingCredentialIssueTicketV1,
};
use crate::credential::enrollment::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialEnrollmentError, CredentialOperationAction,
    CredentialSecretClaimOffer, CredentialSecretInputPresence, CredentialWriterClaimIssuer,
    PendingCredentialSecretOpening,
};

impl PendingCredentialIssueTicketV1 {
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
        mut self,
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
        if self.qualified_receiver.is_some() {
            let receiver = self
                .qualified_receiver
                .take()
                .ok_or(CredentialEnrollmentError::InvalidEvidence)?;
            return self.claim_on_qualified(
                control,
                issuer,
                channel,
                secret_input,
                scope,
                receiver,
            );
        }
        let Self {
            frame,
            binding: retained_binding,
            qualified_receiver: _,
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
}
