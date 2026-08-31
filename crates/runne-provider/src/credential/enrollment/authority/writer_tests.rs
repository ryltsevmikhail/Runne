use super::CredentialWriterAuthorityPair;
use crate::credential::enrollment::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerTarget, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt,
};
use crate::{CredentialVersionRef, ProviderId};

#[test]
fn writer_authority_rejects_foreign_pair_command_and_channel_substitution() {
    let channel = broker_channel([7; 32]);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let first_command = command(1);
    let pending = issuer.issue_pending_claim(&first_command, binding(), &channel);
    let accepted = CredentialBrokerFrame::ClaimAccepted {
        operation_id: first_command.operation_id(),
        attempt: first_command.ticket_attempt(),
    };
    let authorization = issuer
        .claim_accepted(pending, accepted, &first_command, binding(), &channel)
        .unwrap();
    assert!(
        effects
            .authorize(authorization, command(2), binding(), &channel)
            .is_err()
    );

    let foreign_pending = CredentialWriterAuthorityPair::new()
        .split()
        .0
        .issue_pending_claim(&command(3), binding(), &channel);
    let accepted = CredentialBrokerFrame::ClaimAccepted {
        operation_id: CredentialOperationId::from_bytes([3; 16]).unwrap(),
        attempt: CredentialTicketAttempt::new(1).unwrap(),
    };
    assert!(
        issuer
            .claim_accepted(foreign_pending, accepted, &command(3), binding(), &channel)
            .is_err()
    );

    let other_channel = broker_channel([8; 32]);
    let pending = issuer.issue_pending_claim(&command(4), binding(), &channel);
    let accepted = CredentialBrokerFrame::ClaimAccepted {
        operation_id: CredentialOperationId::from_bytes([4; 16]).unwrap(),
        attempt: CredentialTicketAttempt::new(1).unwrap(),
    };
    assert!(
        issuer
            .claim_accepted(pending, accepted, &command(4), binding(), &other_channel)
            .is_err()
    );
}

#[test]
fn writer_authority_consumes_one_matching_command() {
    let channel = broker_channel([7; 32]);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let command = command(1);
    let pending = issuer.issue_pending_claim(&command, binding(), &channel);
    let authorization = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding(),
            &channel,
        )
        .unwrap();
    assert_eq!(
        effects
            .authorize(authorization, command, binding(), &channel)
            .unwrap()
            .operation_id()
            .as_bytes(),
        [1; 16]
    );
}

#[test]
fn writer_effect_rejects_foreign_authority_binding_and_channel() {
    let channel = broker_channel([7; 32]);
    let other_channel = broker_channel([8; 32]);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let foreign_effects = CredentialWriterAuthorityPair::new().split().1;

    let authorization = accepted(&issuer, command(5), &channel, binding());
    assert!(
        foreign_effects
            .authorize(authorization, command(5), binding(), &channel)
            .is_err()
    );

    let authorization = accepted(&issuer, command(6), &channel, binding());
    assert!(
        effects
            .authorize(authorization, command(6), measured(10), &channel)
            .is_err()
    );

    let authorization = accepted(&issuer, command(7), &channel, binding());
    assert!(
        effects
            .authorize(authorization, command(7), binding(), &other_channel)
            .is_err()
    );
}

fn accepted(
    issuer: &super::CredentialWriterClaimIssuer,
    command: CredentialBrokerCommand,
    channel: &BrokerChannelBinding,
    binding: CredentialBindingDigest,
) -> super::ClaimedWriterAuthorization {
    let pending = issuer.issue_pending_claim(&command, binding, channel);
    issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding,
            channel,
        )
        .unwrap()
}

fn broker_channel(bytes: [u8; 32]) -> BrokerChannelBinding {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    measurements.broker_channel_binding(bytes).unwrap()
}
fn command(id: u8) -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([id; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}
fn binding() -> CredentialBindingDigest {
    measured(9)
}
fn measured(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
