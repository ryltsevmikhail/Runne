use super::super::{CredentialMaterial, CredentialMutationGrant, CredentialServiceProtocolCodec};
use super::support::{digest, writer_plan_for_action_with_grant};
use crate::{
    CredentialBrokerFrame, CredentialEnrollmentAuthorityPair, CredentialOperationAction,
    CredentialWriterAuthorityPair,
};
use std::cell::Cell;

#[test]
fn legacy_cleanup_context_requires_retained_effect_domain_binding_and_channel() {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([7; 32]).unwrap();
    let other_channel = measurements.broker_channel_binding([8; 32]).unwrap();
    let (_, effects) = CredentialWriterAuthorityPair::new().split();
    let (_, foreign) = CredentialWriterAuthorityPair::new().split();
    let verifier = effects.legacy_read_verifier(digest(9), &channel);
    assert!(
        verifier
            .validate_effect_context(&effects, digest(9), &channel)
            .is_ok()
    );
    for (authority, binding, channel) in [
        (&foreign, digest(9), &channel),
        (&effects, digest(10), &channel),
        (&effects, digest(9), &other_channel),
    ] {
        assert!(
            verifier
                .validate_effect_context(authority, binding, channel)
                .is_err()
        );
    }
}

#[test]
fn legacy_read_consumer_rejects_foreign_domain_binding_and_channel() {
    let grant = CredentialMutationGrant::from_wire([61; 32]).unwrap();
    let (command, _, handoff) =
        writer_plan_for_action_with_grant(CredentialOperationAction::MigrateLegacy, grant.digest());
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([7; 32]).unwrap();
    let other_channel = measurements.broker_channel_binding([8; 32]).unwrap();
    let binding = digest(9);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let (_, foreign_effects) = CredentialWriterAuthorityPair::new().split();
    let ticket_bytes =
        crate::CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::IssueTicket {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
            ticket: crate::RawCredentialTicket::from_decoded([63; 32]).unwrap(),
            channel_binding: channel.digest().as_bytes(),
            binding,
            command: command.clone(),
        })
        .unwrap();
    let ticket =
        crate::PendingCredentialIssueTicketV1::read_from(&mut std::io::Cursor::new(ticket_bytes))
            .unwrap();
    assert!(
        ticket
            .legacy_read_verifier(&effects, &other_channel)
            .is_err()
    );
    let expected = ticket.legacy_read_verifier(&effects, &channel).unwrap();
    let foreign = foreign_effects.legacy_read_verifier(binding, &channel);
    let wrong_binding = effects.legacy_read_verifier(digest(10), &channel);
    let wrong_channel = effects.legacy_read_verifier(binding, &other_channel);
    let pending = issuer.issue_pending_claim(&command, binding, &channel);
    let authorization = issuer
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
    let bytes = CredentialServiceProtocolCodec::encode_writer_broker_handoff(handoff, grant)
        .unwrap()
        .into_transport_bytes();
    CredentialServiceProtocolCodec::decode_authenticated_writer_legacy_handoff(
        &bytes,
        authorization,
        &effects,
        &channel,
        binding,
        |read| {
            assert!(expected.validate(&read).is_ok());
            for verifier in [&foreign, &wrong_binding, &wrong_channel] {
                assert_eq!(
                    verifier.validate(&read),
                    Err(crate::CredentialEnrollmentError::InvalidEvidence)
                );
            }
            CredentialMaterial::from_bytes(vec![62; 32])
                .and_then(|material| crate::CredentialLegacySourceMaterial::new(material, [73; 16]))
        },
    )
    .unwrap();
}

#[test]
fn legacy_read_token_rejects_wrong_action_channel_and_issuer_before_callback() {
    for changed in ["action", "channel", "issuer"] {
        let action = if changed == "action" {
            CredentialOperationAction::Pair
        } else {
            CredentialOperationAction::MigrateLegacy
        };
        let grant = CredentialMutationGrant::from_wire([61; 32]).unwrap();
        let (command, _, handoff) = writer_plan_for_action_with_grant(action, grant.digest());
        let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
        let channel = measurements.broker_channel_binding([7; 32]).unwrap();
        let other_channel = measurements.broker_channel_binding([8; 32]).unwrap();
        let binding = digest(9);
        let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
        let (_, other_effects) = CredentialWriterAuthorityPair::new().split();
        let pending = issuer.issue_pending_claim(&command, binding, &channel);
        let authorization = issuer
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
        let bytes = CredentialServiceProtocolCodec::encode_writer_broker_handoff(handoff, grant)
            .unwrap()
            .into_transport_bytes();
        let reads = Cell::new(0);
        let result = CredentialServiceProtocolCodec::decode_authenticated_writer_legacy_handoff(
            &bytes,
            authorization,
            if changed == "issuer" {
                &other_effects
            } else {
                &effects
            },
            if changed == "channel" {
                &other_channel
            } else {
                &channel
            },
            binding,
            |_| {
                reads.set(reads.get() + 1);
                CredentialMaterial::from_bytes(vec![62; 32]).and_then(|material| {
                    crate::CredentialLegacySourceMaterial::new(material, [73; 16])
                })
            },
        );
        assert!(result.is_err(), "{changed}");
        assert_eq!(reads.get(), 0, "{changed} must not mint a read token");
    }
}
