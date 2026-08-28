use std::io::{Read, Write};

use runne_provider::{
    CredentialBrokerCommand, CredentialBrokerTarget, CredentialFence, CredentialLifecycleRevision,
    CredentialOperationAction, CredentialOperationId, CredentialSecretClaimOffer,
    CredentialSecretOfferCodec, CredentialTicketAttempt, CredentialVersionRef, ProviderId,
};

use super::*;

#[test]
fn daemon_owned_rendezvous_moves_each_endpoint_once_and_binds_the_pair() {
    let mut rendezvous = DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    assert_ne!(rendezvous.channel_binding(), [0; 32]);
    let authority = rendezvous.take_daemon_authority().unwrap();
    let (mut daemon, _, _, _) = authority.into_parts().unwrap();
    let mut writer = rendezvous.take_writer_endpoint().unwrap();
    assert!(matches!(
        rendezvous.take_daemon_authority(),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
    assert!(matches!(
        rendezvous.take_writer_endpoint(),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));

    writer.write_all(b"claim").unwrap();
    let mut frame = [0; 5];
    daemon.read_exact(&mut frame).unwrap();
    assert_eq!(frame, *b"claim");
}

#[test]
fn rendezvous_public_key_and_channel_verify_its_one_shot_publication() {
    let mut rendezvous = DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let public_key = rendezvous.publication_public_key();
    assert_ne!(public_key, [0; 32]);
    let authority = rendezvous.take_daemon_authority().unwrap();
    assert_eq!(authority.publication_public_key(), public_key);
    let (_, binding, signer, stable_key) = authority.into_parts().unwrap();
    let offer = offer(binding);
    let replay =
        CredentialSecretOfferCodec::decode(&CredentialSecretOfferCodec::encode(&offer)).unwrap();
    let publication = signer.sign(offer);

    assert_eq!(stable_key, public_key);
    assert!(
        runne_provider::daemon_credential_publication_test_support::verify(
            public_key,
            binding,
            replay,
            publication,
        )
        .is_ok()
    );
    assert_eq!(rendezvous.publication_public_key(), public_key);
    assert!(matches!(
        rendezvous.take_daemon_authority(),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
}

fn offer(binding: [u8; 32]) -> CredentialSecretClaimOffer {
    let provider = ProviderId::new("openai").unwrap();
    let operation = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let command = CredentialBrokerCommand::new(
        operation,
        CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap();
    CredentialSecretClaimOffer::prepare(
        &command,
        runne_provider::CredentialBindingDigest::from_measured(binding).unwrap(),
    )
    .unwrap()
    .0
}
