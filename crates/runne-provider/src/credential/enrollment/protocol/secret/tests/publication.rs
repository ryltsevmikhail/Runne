use crate::{
    CredentialBrokerCommand, CredentialFence, CredentialLifecycleRevision,
    CredentialOperationAction, CredentialOperationId, CredentialSecretClaimOffer,
    CredentialSecretPublication, CredentialSecretPublicationCodec, CredentialTicketAttempt,
    CredentialVersionRef, ProviderId,
};
use ring::signature::KeyPair;

use super::super::publication::{
    CredentialSecretPublicationVerifier, VerifiedCredentialSecretOffer,
};
use super::{binding, channel, channel_from, command};

#[test]
fn publication_verifier_consumes_its_one_shot_verification_capability() {
    let command = command(60);
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding(61)).unwrap();
    let channel = channel();
    let (daemon, publication) = super::super::publication::fixture_publication(&offer, &channel);
    let verify: fn(
        CredentialSecretPublicationVerifier,
        CredentialSecretClaimOffer,
        CredentialSecretPublication,
    ) -> Result<VerifiedCredentialSecretOffer, crate::CredentialEnrollmentError> =
        CredentialSecretPublicationVerifier::verify;

    assert!(
        verify(
            CredentialSecretPublicationVerifier::new(daemon, &channel),
            offer,
            publication,
        )
        .is_ok()
    );
}

#[test]
fn publication_rejects_foreign_configured_verifier_key() {
    let command = command(61);
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding(62)).unwrap();
    let channel = channel();
    let (_, publication) = super::super::publication::fixture_publication(&offer, &channel);
    let foreign_key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
    let foreign_public_key = foreign_key.public_key().as_ref().try_into().unwrap();

    assert!(
        CredentialSecretPublicationVerifier::new(foreign_public_key, &channel)
            .verify(offer, publication)
            .is_err()
    );
}

#[test]
fn publication_rejects_foreign_configured_verifier_channel() {
    let command = command(63);
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding(64)).unwrap();
    let channel = channel();
    let (daemon, publication) = super::super::publication::fixture_publication(&offer, &channel);

    assert!(
        CredentialSecretPublicationVerifier::new(daemon, &channel_from([9; 32]))
            .verify(offer, publication)
            .is_err()
    );
}

#[test]
fn publication_rejects_replay_against_wrong_expected_operation() {
    let first_command = command(65);
    let (first_offer, _) =
        CredentialSecretClaimOffer::prepare(&first_command, binding(66)).unwrap();
    let channel = channel();
    let (daemon, publication) =
        super::super::publication::fixture_publication(&first_offer, &channel);
    let second_command = command(67);
    let (second_offer, _) =
        CredentialSecretClaimOffer::prepare(&second_command, binding(66)).unwrap();

    assert!(
        CredentialSecretPublicationVerifier::new(daemon, &channel)
            .verify(second_offer, publication)
            .is_err()
    );
}

#[test]
fn publication_rejects_replay_against_wrong_expected_attempt() {
    let command = command(68);
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding(69)).unwrap();
    let channel = channel();
    let (daemon, publication) = super::super::publication::fixture_publication(&offer, &channel);
    let wrong_attempt = command_with_attempt(68, 2);
    let (wrong_offer, _) =
        CredentialSecretClaimOffer::prepare(&wrong_attempt, binding(69)).unwrap();

    assert!(
        CredentialSecretPublicationVerifier::new(daemon, &channel)
            .verify(wrong_offer, publication)
            .is_err()
    );
}

fn command_with_attempt(id: u8, attempt: u64) -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([id; 16]).unwrap(),
        CredentialTicketAttempt::new(attempt).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        crate::CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

#[test]
fn publication_rejects_replay_against_wrong_expected_claim() {
    let expected_command = command(70);
    let (offer, _) = CredentialSecretClaimOffer::prepare(&expected_command, binding(71)).unwrap();
    let channel = channel();
    let (daemon, publication) = super::super::publication::fixture_publication(&offer, &channel);
    let other_command = command(70);
    let (other_offer, _) =
        CredentialSecretClaimOffer::prepare(&other_command, binding(72)).unwrap();

    assert!(
        CredentialSecretPublicationVerifier::new(daemon, &channel)
            .verify(other_offer, publication)
            .is_err()
    );
}

#[test]
fn publication_codec_rejects_wrong_sequence_malformed_and_trailing_forms() {
    let command = command(73);
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding(74)).unwrap();
    let channel = channel();
    let (_, publication) = super::super::publication::fixture_publication(&offer, &channel);
    let encoded = CredentialSecretPublicationCodec::encode(&publication);
    let mut wrong_sequence = encoded;
    wrong_sequence[192] ^= 1;
    let mut wrong_version = encoded;
    wrong_version[0] ^= 1;

    assert!(CredentialSecretPublicationCodec::decode(&wrong_sequence).is_err());
    assert!(CredentialSecretPublicationCodec::decode(&wrong_version).is_err());
    assert!(CredentialSecretPublicationCodec::decode(&encoded[..256]).is_err());
    assert!(
        CredentialSecretPublicationCodec::decode(&[encoded.as_slice(), &[0]].concat()).is_err()
    );
}
