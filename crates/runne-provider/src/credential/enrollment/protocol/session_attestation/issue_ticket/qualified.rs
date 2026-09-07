use super::super::qualified::{
    CredentialWriterQualifiedAckCodec, CredentialWriterQualifiedAckV1,
    CredentialWriterQualifiedPreludeCodec, SignedCredentialWriterSessionAttestationV2,
    WriterQualificationReceiver,
};
use super::super::{
    CredentialIssueTicketBindingV1, CredentialSecretInputPresence, CredentialWriterCommandKindV1,
    CredentialWriterCommandScopeV1, PendingCredentialIssueTicketV1,
};
use crate::credential::enrollment::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialEnrollmentError, CredentialOperationAction, CredentialSecretClaimOffer,
    CredentialWriterClaimIssuer, PendingCredentialSecretOpening,
};

impl PendingCredentialIssueTicketV1 {
    /// Retains the verified V2 attestation for automatic qualified claiming.
    pub fn with_qualified_attestation(
        mut self,
        attestation: SignedCredentialWriterSessionAttestationV2,
    ) -> Self {
        self.qualified_receiver = Some(WriterQualificationReceiver::new(attestation));
        self
    }

    /// Reports whether this move-only ticket carries the required V2 route.
    #[doc(hidden)]
    #[must_use]
    pub fn is_qualified(&self) -> bool {
        self.qualified_receiver.is_some()
    }

    /// Claims through the required V2 prelude, ACK, and ClaimAccepted phases.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn claim_on_qualified<R: std::io::Read + std::io::Write>(
        self,
        control: &mut R,
        issuer: &CredentialWriterClaimIssuer,
        channel: &BrokerChannelBinding,
        secret_input: CredentialSecretInputPresence,
        scope: CredentialWriterCommandScopeV1,
        receiver: WriterQualificationReceiver,
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
        if !receiver.attestation().is_current_now()
            || !receiver.attestation().matches_pending_issue_ticket(&self)
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let daemon_public_key = receiver.attestation().publication_public_key;
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
        let (secret_offer, pending_opening) = if expects_secret {
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
        let prelude = CredentialWriterQualifiedPreludeCodec::read_from(control, daemon_public_key)?;
        let verified = receiver.verify_prelude(prelude, unix_seconds()?)?;
        let pending_claim =
            CredentialWriterClaimIssuer::retain_qualification_fault(pending_claim, verified.fault);
        let ack = CredentialWriterQualifiedAckV1::new(
            verified.attestation_digest,
            verified.prelude_digest,
        );
        control
            .write_all(&CredentialWriterQualifiedAckCodec::encode(&ack))
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
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

fn unix_seconds() -> Result<u64, CredentialEnrollmentError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)
}
