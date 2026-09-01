use super::{
    CredentialIssueTicketBindingV1, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionAttestationSigner, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1,
};
use crate::credential::enrollment::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerTarget, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialSecretClaimOffer,
    RawCredentialTicket,
};
use crate::{CredentialVersionRef, ProviderId};

pub(in crate::credential::enrollment::protocol) fn attested_publication_signer_for_test(
    channel: &BrokerChannelBinding,
    offer: &CredentialSecretClaimOffer,
) -> Result<super::DaemonCredentialSecretPublicationSigner, super::CredentialEnrollmentError> {
    let provider =
        ProviderId::new("openai").map_err(|_| super::CredentialEnrollmentError::InvalidEvidence)?;
    let command = CredentialBrokerCommand::new(
        offer.operation_id,
        offer.attempt,
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(
            CredentialVersionRef::new(provider, 1)
                .map_err(|_| super::CredentialEnrollmentError::InvalidEvidence)?,
        ),
        CredentialLifecycleRevision::new(1)?,
        CredentialFence::new(1)?,
        None,
    )?;
    let frame = CredentialBrokerFrame::IssueTicket {
        operation_id: offer.operation_id,
        attempt: offer.attempt,
        ticket: RawCredentialTicket::from_decoded([1; 32])?,
        channel_binding: channel.digest().as_bytes(),
        binding: offer.claim_binding,
        command,
    };
    let claims = CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            offer.operation_id,
            offer.attempt,
            CredentialIssueTicketBindingV1::from_issue_ticket(&frame)?,
            offer.claim_binding,
            CredentialInstallationOwnerId::from_bytes([2; 32])?,
            digest(3)?,
            1,
            2,
        )?,
        CredentialWriterSessionRuntimeClaimsV1::new(
            digest(4)?,
            digest(5)?,
            digest(6)?,
            1,
            1,
            digest(7)?,
        )?,
        CredentialWriterSessionProcessClaimsV1::new(
            digest(8)?,
            digest(9)?,
            digest(10)?,
            digest(11)?,
            digest(12)?,
            digest(13)?,
        )?,
    );
    CredentialWriterSessionAttestationSigner::generate(channel.digest().as_bytes())?
        .sign(claims)
        .map(|(_, signer)| signer)
}

fn digest(value: u8) -> Result<CredentialBindingDigest, super::CredentialEnrollmentError> {
    CredentialBindingDigest::from_measured([value; 32])
}
