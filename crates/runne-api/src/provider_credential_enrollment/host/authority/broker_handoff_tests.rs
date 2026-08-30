//! Codec tests for the broker writer-handoff control frames.

use super::*;
use crate::LaunchSecret;

fn handoff_keys(seed: u8) -> CredentialBrokerTransferAuthenticator {
    CredentialBrokerTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([seed; 32]).unwrap().derive_keys(),
    )
}

fn handoff_context() -> ProviderCredentialBrokerHandoffContext {
    ProviderCredentialBrokerHandoffContext::new(
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2],
        1,
        [3; 32],
    )
    .unwrap()
}

fn signed_offer(
    context: &ProviderCredentialBrokerHandoffContext,
    keys: &CredentialBrokerTransferAuthenticator,
) -> ProviderCredentialBrokerHandoffFrame {
    ProviderCredentialBrokerHandoffFrame::offer(
        context.clone(),
        ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        100,
        30_100,
        [9; 16],
        keys,
    )
    .unwrap()
}

#[test]
fn broker_handoff_offer_ready_ack_round_trip_and_bind_the_nonce() {
    let context = handoff_context();
    let desktop = handoff_keys(11);
    let offer = signed_offer(&context, &desktop);
    let decoded = ProviderCredentialBrokerHandoffFrame::decode_and_verify(
        &offer.encode_frame(),
        &desktop,
        &context,
        ProviderCredentialBrokerHandoffFrame::PHASE_OFFER,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        [0; 16],
        100,
    )
    .unwrap();
    assert_eq!(decoded.nonce(), &[9; 16]);

    let daemon = handoff_keys(11);
    let ready = decoded.ready(&daemon);
    ProviderCredentialBrokerHandoffFrame::decode_and_verify(
        &ready.encode_frame(),
        &desktop,
        &context,
        ProviderCredentialBrokerHandoffFrame::PHASE_READY,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        [9; 16],
        101,
    )
    .unwrap();
    let acknowledgement = ready.acknowledgement(&daemon);
    ProviderCredentialBrokerHandoffFrame::decode_and_verify(
        &acknowledgement.encode_frame(),
        &desktop,
        &context,
        ProviderCredentialBrokerHandoffFrame::PHASE_ACK,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
        [9; 16],
        102,
    )
    .unwrap_err();
}

#[test]
fn broker_handoff_frames_reject_tampering_substitution_and_staleness() {
    let context = handoff_context();
    let desktop = handoff_keys(11);
    let offer = signed_offer(&context, &desktop);

    let mut tampered = offer.encode_frame();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        ProviderCredentialBrokerHandoffFrame::decode_and_verify(
            &tampered,
            &desktop,
            &context,
            ProviderCredentialBrokerHandoffFrame::PHASE_OFFER,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
            [0; 16],
            100,
        ),
        Err(LaunchAuthorityError::ReadinessProofMismatch)
    ));

    assert!(matches!(
        ProviderCredentialBrokerHandoffFrame::decode_and_verify(
            &offer.encode_frame(),
            &desktop,
            &context,
            ProviderCredentialBrokerHandoffFrame::PHASE_OFFER,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_EVIDENCE,
            [0; 16],
            100,
        ),
        Err(LaunchAuthorityError::InvalidContract)
    ));

    let stranger = handoff_keys(12);
    assert!(matches!(
        ProviderCredentialBrokerHandoffFrame::decode_and_verify(
            &offer.encode_frame(),
            &stranger,
            &context,
            ProviderCredentialBrokerHandoffFrame::PHASE_OFFER,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
            [0; 16],
            100,
        ),
        Err(LaunchAuthorityError::ReadinessProofMismatch)
    ));

    assert!(matches!(
        ProviderCredentialBrokerHandoffFrame::decode_and_verify(
            &offer.encode_frame(),
            &desktop,
            &context,
            ProviderCredentialBrokerHandoffFrame::PHASE_OFFER,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
            [0; 16],
            30_101,
        ),
        Err(LaunchAuthorityError::OwnershipMismatch)
    ));

    let daemon = handoff_keys(11);
    let ready = offer.ready(&daemon);
    assert!(matches!(
        ProviderCredentialBrokerHandoffFrame::decode_and_verify(
            &ready.encode_frame(),
            &desktop,
            &context,
            ProviderCredentialBrokerHandoffFrame::PHASE_READY,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
            [8; 16],
            101,
        ),
        Err(LaunchAuthorityError::OwnershipMismatch)
    ));

    assert!(ProviderCredentialBrokerHandoffFrame::offer(
        context.clone(),
        ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        100,
        100 + BROKER_HANDOFF_WINDOW_MILLIS + 1,
        [9; 16],
        &desktop,
    )
    .is_err());
    assert!(is_broker_handoff_frame(&offer.encode_frame()));
    assert!(!is_broker_handoff_frame(&[0; 64]));
}
