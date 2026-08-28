use crate::{CredentialBrokerFrame, CredentialWriterAuthorityPair};

use super::{binding, channel, command};

#[test]
fn secret_opening_authorization_rejects_foreign_pair_before_decryption() {
    let command = command(31);
    let binding = binding(32);
    let channel = channel();
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();
    let (_, foreign_effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(&command, binding, &channel);
    let claimed = issuer
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
        foreign_effects
            .authorize_secret_opening(claimed, command, binding, &channel)
            .is_err()
    );
}

#[test]
fn secret_opening_authorization_rejects_wrong_command_before_decryption() {
    let expected_command = command(33);
    let binding = binding(34);
    let channel = channel();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(&expected_command, binding, &channel);
    let claimed = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: expected_command.operation_id(),
                attempt: expected_command.ticket_attempt(),
            },
            &expected_command,
            binding,
            &channel,
        )
        .unwrap();

    assert!(
        effects
            .authorize_secret_opening(claimed, command(35), binding, &channel)
            .is_err()
    );
}

#[test]
fn secret_opening_authorization_rejects_wrong_claim_binding_before_decryption() {
    let command = command(36);
    let channel = channel();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(&command, binding(37), &channel);
    let claimed = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding(37),
            &channel,
        )
        .unwrap();

    assert!(
        effects
            .authorize_secret_opening(claimed, command, binding(38), &channel)
            .is_err()
    );
}

#[test]
fn secret_opening_authorization_rejects_wrong_channel_before_decryption() {
    let command = command(39);
    let binding = binding(40);
    let channel = channel();
    let other_channel = super::channel_from([8; 32]);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(&command, binding, &channel);
    let claimed = issuer
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
        effects
            .authorize_secret_opening(claimed, command, binding, &other_channel)
            .is_err()
    );
}
