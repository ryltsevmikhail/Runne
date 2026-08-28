use crate::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialSecretClaimOffer, CredentialTicketAttempt, CredentialVersionRef, ProviderId,
    RawCredentialTicket,
};

#[test]
fn v4_claim_round_trips_in_its_fixed_width_form() {
    let (operation_id, attempt, command) = command();
    let binding = CredentialBindingDigest::from_measured([8; 32]).unwrap();
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding).unwrap();
    let frame = CredentialBrokerFrame::Claim {
        operation_id,
        attempt,
        ticket: RawCredentialTicket::generate().unwrap(),
        binding,
        secret_offer: Some(offer),
    };

    let bytes = CredentialBrokerFrameCodec::encode(frame).unwrap();
    assert_eq!(bytes[0], 4);
    assert_eq!(bytes.len(), 213);
    let decoded = CredentialBrokerFrameCodec::decode(&bytes).unwrap();
    assert_eq!(CredentialBrokerFrameCodec::encode(decoded).unwrap(), bytes);
}

#[test]
fn v4_claim_rejects_noncanonical_absent_offer_slot() {
    let (operation_id, attempt, _) = command();
    let binding = CredentialBindingDigest::from_measured([9; 32]).unwrap();
    let mut bytes = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::Claim {
        operation_id,
        attempt,
        ticket: RawCredentialTicket::generate().unwrap(),
        binding,
        secret_offer: None,
    })
    .unwrap();
    assert_eq!(bytes.len(), 213);
    bytes[91] = 1;
    assert!(CredentialBrokerFrameCodec::decode(&bytes).is_err());
}

#[test]
fn v4_claim_rejects_offer_with_mismatched_outer_transcript() {
    let (operation_id, attempt, command) = command();
    let binding = CredentialBindingDigest::from_measured([10; 32]).unwrap();
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding).unwrap();
    let mut bytes = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::Claim {
        operation_id,
        attempt,
        ticket: RawCredentialTicket::generate().unwrap(),
        binding,
        secret_offer: Some(offer),
    })
    .unwrap();
    bytes[2] ^= 1;
    assert!(CredentialBrokerFrameCodec::decode(&bytes).is_err());
}

#[test]
fn v3_claim_is_rejected_without_a_dual_decoder() {
    let (_, _, _) = command();
    let bytes = [3_u8, 2];
    assert!(CredentialBrokerFrameCodec::decode(&bytes).is_err());
}

fn command() -> (
    CredentialOperationId,
    CredentialTicketAttempt,
    CredentialBrokerCommand,
) {
    let operation_id = CredentialOperationId::from_bytes([7; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(2).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let command = CredentialBrokerCommand::new(
        operation_id,
        attempt,
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap();
    (operation_id, attempt, command)
}
