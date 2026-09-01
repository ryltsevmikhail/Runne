use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroizing;

use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerTarget, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialSecretClaimOffer, CredentialSecretEnvelopeCodec, CredentialSecretOfferCodec,
    CredentialTicketAttempt, CredentialVersionRef, CredentialWriterAuthorityPair, ProviderId,
};

use super::{AuthenticatedPairSecretSealer, publication_message};

#[test]
fn authenticated_platform_sealer_produces_a_writer_openable_envelope() {
    let command = command();
    let binding = binding();
    let (offer, opening) = CredentialSecretClaimOffer::prepare(&command, binding).unwrap();
    let (frame, daemon, channel) = relay(&offer);
    let envelope = prepared_sealer(daemon, channel)
        .seal(&frame, Zeroizing::new(b"credential".to_vec()))
        .unwrap();
    let envelope = CredentialSecretEnvelopeCodec::decode(&envelope).unwrap();
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding(channel).unwrap();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
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
    let opened = effects
        .authorize_and_consume_sealed_pair(
            authorization,
            command,
            binding,
            &channel,
            opening,
            envelope,
            |secret| {
                assert_eq!(secret, b"credential");
                Ok::<_, ()>(())
            },
        )
        .unwrap();
    assert_eq!(opened, Ok(()));
}

#[test]
fn platform_sealer_rejects_wrong_authenticated_facts_and_tamper() {
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command(), binding()).unwrap();
    let (frame, daemon, channel) = relay(&offer);
    for (key, binding) in [([9; 32], channel), (daemon, [10; 32])] {
        assert!(
            prepared_sealer(key, binding)
                .seal(&frame, Zeroizing::new(b"credential".to_vec()))
                .is_err()
        );
    }
    for offset in [0, 12, frame.len() - 1] {
        let mut tampered = frame;
        tampered[offset] ^= 1;
        assert!(
            prepared_sealer(daemon, channel)
                .seal(&tampered, Zeroizing::new(b"credential".to_vec()))
                .is_err()
        );
    }
}

fn prepared_sealer(
    daemon_public_key: [u8; 32],
    channel: [u8; 32],
) -> AuthenticatedPairSecretSealer {
    let (receiver, _sender) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = runne_api::LaunchSecret::from_bytes([44; 32])
        .unwrap()
        .derive_keys();
    let authenticator =
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let prepared = super::super::prepare_daemon_owned_writer_endpoint_handoff(
        receiver,
        &authenticator,
        channel,
        daemon_public_key,
    )
    .unwrap();
    prepared.into_pair_spawn_parts().3
}

fn relay(offer: &CredentialSecretClaimOffer) -> ([u8; 388], [u8; 32], [u8; 32]) {
    let offer = CredentialSecretOfferCodec::encode(offer);
    let channel = [8; 32];
    let signing = SigningKey::from_bytes(&[7; 32]);
    let daemon = signing.verifying_key().to_bytes();
    let mut publication = [0; 257];
    publication[0] = 1;
    publication[1..121].copy_from_slice(&offer[2..122]);
    publication[121..153].copy_from_slice(&channel);
    publication[153..185].copy_from_slice(&daemon);
    publication[185..193].copy_from_slice(&1_u64.to_be_bytes());
    let signature = signing.sign(&publication_message(&publication));
    publication[193..].copy_from_slice(&signature.to_bytes());
    let mut frame = [0; 388];
    frame[..8].copy_from_slice(b"GCSREL01");
    frame[8] = 1;
    frame[9..131].copy_from_slice(&offer);
    frame[131..].copy_from_slice(&publication);
    (frame, daemon, channel)
}

fn command() -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([4; 16]).unwrap(),
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
    CredentialBindingDigest::from_measured([5; 32]).unwrap()
}
