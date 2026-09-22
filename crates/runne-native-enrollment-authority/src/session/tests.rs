#![cfg(test)]

use super::AuthenticatedProviderCredentialWriterSession;
use runne_provider::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerTarget, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt, CredentialVersionRef, ProviderId,
};

#[test]
fn authenticated_session_splits_once_into_matched_claim_and_effect() {
    let session = AuthenticatedProviderCredentialWriterSession::mint_for_test();
    let (claim, effect) = session.split();
    let channel = broker_channel([7; 32]);
    let command = command(9);
    let binding = measured(11);
    let pending = claim
        .issuer
        .issue_pending_claim(&command, binding, &channel);
    let authorization = claim
        .issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding,
            &channel,
        )
        .unwrap();

    let admitted = effect
        .effects
        .authorize(authorization, command, binding, &channel)
        .unwrap();
    assert_eq!(admitted.operation_id().as_bytes(), [9; 16]);
}

#[test]
fn independently_admitted_sessions_do_not_share_an_effect_seal() {
    let (first_claim, _) = AuthenticatedProviderCredentialWriterSession::mint_for_test().split();
    let (_, second_effect) = AuthenticatedProviderCredentialWriterSession::mint_for_test().split();
    let channel = broker_channel([12; 32]);
    let command = command(13);
    let binding = measured(14);
    let pending = first_claim
        .issuer
        .issue_pending_claim(&command, binding, &channel);
    let authorization = first_claim
        .issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding,
            &channel,
        )
        .unwrap();

    assert!(
        second_effect
            .effects
            .authorize(authorization, command, binding, &channel)
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_claim_parts_reject_synthetic_sessions_without_verified_parts() {
    let (claim, _) = AuthenticatedProviderCredentialWriterSession::mint_for_test().split();
    assert!(
        matches!(
            claim.into_linux_claim_parts(),
            Err("linux session verified parts absent")
        ),
        "only a verifier-produced session may yield Linux claim parts"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_effect_parts_reject_synthetic_sessions_without_verified_parts() {
    let (_, effect) = AuthenticatedProviderCredentialWriterSession::mint_for_test().split();
    assert!(
        matches!(
            effect.into_linux_effect_parts(),
            Err("linux session verified parts absent")
        ),
        "only a verifier-produced session may yield Linux effect parts"
    );
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

fn measured(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
