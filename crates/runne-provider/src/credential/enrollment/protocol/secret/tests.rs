use crate::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerTarget, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialSecretClaimOffer, CredentialSecretEnvelopeCodec, CredentialSecretOfferCodec,
    CredentialTicketAttempt, CredentialVersionRef, CredentialWriterAuthorityPair, ProviderId,
};
use zeroize::Zeroizing;

use super::publication::{CredentialSecretPublicationVerifier, VerifiedCredentialSecretOffer};

#[path = "tests/admission.rs"]
mod admission;
#[path = "tests/eligibility.rs"]
mod eligibility;
#[path = "tests/kat.rs"]
mod kat;
#[path = "tests/publication.rs"]
mod publication;
mod signer;

#[test]
fn sealed_credential_is_relayed_only_after_exact_claim_accepted() {
    let command = command(1);
    let binding = binding(2);
    let (accepted, pending) = verified_offer(&command, binding);
    let envelope = accepted
        .seal(Zeroizing::new(b"credential".to_vec()))
        .unwrap();
    let (authorization, channel) = authorization(&command, binding);
    let opened = pending
        .open_after_claim(authorization, &channel, envelope)
        .unwrap();

    assert_eq!(opened.test_command(), &command);
    assert_eq!(opened.test_material().test_bytes(), b"credential");
}

#[test]
fn sealed_credential_accepts_one_and_4096_byte_single_lines() {
    for credential in [vec![b'a'], vec![b'z'; 4096]] {
        let command = command(4);
        let binding = binding(5);
        let (pending, envelope) = envelope(&command, binding, &credential);
        let (authorization, channel) = authorization(&command, binding);
        let effect = pending
            .open_after_claim(authorization, &channel, envelope)
            .unwrap();
        assert_eq!(effect.test_material().test_bytes(), credential);
    }
}

#[test]
fn sealed_credential_rejects_tampered_transcript_length_tag_and_low_order_peer() {
    let command = command(6);
    let binding = binding(7);
    for mutation in [26, 90, 123, usize::MAX] {
        let (pending, envelope) = envelope(&command, binding, b"credential");
        let mut altered = CredentialSecretEnvelopeCodec::encode(&envelope)
            .unwrap()
            .to_vec();
        match mutation {
            90 => altered[90..122].fill(0),
            usize::MAX => *altered.last_mut().unwrap() ^= 0x80,
            offset => altered[offset] ^= 0x80,
        }
        let decoded = CredentialSecretEnvelopeCodec::decode(&altered);
        if mutation == 123 {
            assert!(decoded.is_err());
        } else {
            let (authorization, channel) = authorization(&command, binding);
            assert!(
                pending
                    .open_after_claim(authorization, &channel, decoded.unwrap())
                    .is_err()
            );
        }
    }
}

#[test]
fn sealed_credential_codecs_reject_nonexact_offer_and_envelope_forms() {
    let command = command(8);
    let binding = binding(9);
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding).unwrap();
    let offer_bytes = CredentialSecretOfferCodec::encode(&offer);
    assert_eq!(offer_bytes.len(), CredentialSecretOfferCodec::BYTES);
    assert!(CredentialSecretOfferCodec::decode(&offer_bytes[..121]).is_err());
    assert!(CredentialSecretOfferCodec::decode(&[offer_bytes.as_slice(), &[0]].concat()).is_err());
    let mut changed_writer_key = offer_bytes;
    changed_writer_key[58] ^= 0x80;
    assert!(CredentialSecretOfferCodec::decode(&changed_writer_key).is_err());

    let (_, envelope) = envelope(&command, binding, b"credential");
    let encoded = CredentialSecretEnvelopeCodec::encode(&envelope).unwrap();
    assert!(CredentialSecretEnvelopeCodec::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
    assert!(
        CredentialSecretEnvelopeCodec::decode(&vec![
            0;
            CredentialSecretEnvelopeCodec::MAX_BYTES + 1
        ])
        .is_err()
    );
}

#[test]
fn sealed_credential_rejects_empty_multiline_and_oversized_plaintext() {
    let command = command(12);
    let binding = binding(13);
    for credential in [
        Vec::new(),
        b"first\nsecond".to_vec(),
        b"contains\0nul".to_vec(),
        vec![b'x'; 4097],
    ] {
        let (accepted, _) = verified_offer(&command, binding);
        assert!(accepted.seal(Zeroizing::new(credential)).is_err());
    }
}

#[test]
fn sealed_credential_uses_fresh_offer_and_sealer_keys() {
    let command = command(10);
    let binding = binding(11);
    let (_, first) = envelope(&command, binding, b"credential");
    let (_, second) = envelope(&command, binding, b"credential");
    assert_ne!(
        CredentialSecretEnvelopeCodec::encode(&first).unwrap(),
        CredentialSecretEnvelopeCodec::encode(&second).unwrap(),
    );
}

#[test]
fn sealed_credential_publication_codec_rejects_sequence_and_trailing_bytes() {
    let command = command(14);
    let binding = binding(15);
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding).unwrap();
    let channel = channel();
    let (_, publication) = super::publication::fixture_publication(&offer, &channel);
    let encoded = crate::CredentialSecretPublicationCodec::encode(&publication);
    assert!(
        crate::CredentialSecretPublicationCodec::decode(&[encoded.as_slice(), &[0]].concat())
            .is_err()
    );
    let mut bad_sequence = encoded;
    bad_sequence[192] ^= 1;
    assert!(crate::CredentialSecretPublicationCodec::decode(&bad_sequence).is_err());
}

#[test]
fn sealed_credential_signed_all_zero_writer_key_cannot_seal() {
    let command = command(16);
    let binding = binding(17);
    let (mut offer, _) = CredentialSecretClaimOffer::prepare(&command, binding).unwrap();
    offer.writer_public_key = [0; 32];
    offer.offer_binding = super::cipher::offer_binding(
        offer.operation_id,
        offer.attempt,
        offer.claim_binding,
        offer.writer_public_key,
    );
    let channel = channel();
    let (daemon, publication) = super::publication::fixture_publication(&offer, &channel);
    let verified = CredentialSecretPublicationVerifier::new(daemon, &channel)
        .verify(offer, publication)
        .unwrap();
    assert!(
        verified
            .seal(Zeroizing::new(b"credential".to_vec()))
            .is_err()
    );
}

#[test]
fn sealed_credential_offer_binding_matches_independent_sha256_vector() {
    let digest = super::cipher::offer_binding(
        CredentialOperationId::from_bytes([1; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        CredentialBindingDigest::from_measured([2; 32]).unwrap(),
        [3; 32],
    );
    assert_eq!(
        digest.as_bytes(),
        [
            0x77, 0x03, 0x8e, 0x72, 0xfd, 0x7b, 0xad, 0xe7, 0x4b, 0x6d, 0x1a, 0x11, 0x1c, 0xe9,
            0x6a, 0xf3, 0x22, 0x52, 0xfe, 0x4d, 0xd0, 0x7f, 0x70, 0x5f, 0x4a, 0x99, 0xf8, 0x76,
            0xcf, 0x03, 0xeb, 0x37,
        ]
    );
}

fn envelope(
    command: &CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    credential: &[u8],
) -> (
    crate::PendingCredentialSecretOpening,
    crate::SealedCredentialEnvelope,
) {
    let (accepted, pending) = verified_offer(command, binding);
    (
        pending,
        accepted.seal(Zeroizing::new(credential.to_vec())).unwrap(),
    )
}

fn verified_offer(
    command: &CredentialBrokerCommand,
    binding: CredentialBindingDigest,
) -> (
    VerifiedCredentialSecretOffer,
    crate::PendingCredentialSecretOpening,
) {
    let (offer, pending) = CredentialSecretClaimOffer::prepare(command, binding).unwrap();
    let channel = channel();
    let (daemon, publication) = super::publication::fixture_publication(&offer, &channel);
    let verified = CredentialSecretPublicationVerifier::new(daemon, &channel)
        .verify(offer, publication)
        .unwrap();
    (verified, pending)
}

fn authorization(
    command: &CredentialBrokerCommand,
    binding: CredentialBindingDigest,
) -> (
    crate::credential::enrollment::authority::writer::AuthorizedCredentialSecretOpening,
    BrokerChannelBinding,
) {
    let channel = channel();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(command, binding, &channel);
    let claimed = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            command,
            binding,
            &channel,
        )
        .unwrap();
    let authorized = effects
        .authorize_secret_opening(claimed, command.clone(), binding, &channel)
        .unwrap();
    (authorized, channel)
}

fn channel() -> BrokerChannelBinding {
    channel_from([7; 32])
}

fn channel_from(bytes: [u8; 32]) -> BrokerChannelBinding {
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

fn binding(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
