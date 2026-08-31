use crate::daemon_credential_publication::CredentialSecretPublicationSigner;
use crate::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerTarget, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialSecretClaimOffer, CredentialSecretOfferCodec, CredentialSecretPublicationCodec,
    CredentialTicketAttempt, CredentialVersionRef, ProviderId,
};

use super::super::publication::CredentialSecretPublicationVerifier;

#[test]
fn daemon_signer_signs_one_offer_for_its_exact_channel() {
    let command = command();
    let claim = CredentialBindingDigest::from_measured([71; 32]).unwrap();
    let channel = super::channel_from([72; 32]);
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, claim).unwrap();
    let replay =
        CredentialSecretOfferCodec::decode(&CredentialSecretOfferCodec::encode(&offer)).unwrap();
    let signer = CredentialSecretPublicationSigner::generate([72; 32]).unwrap();
    let public_key = signer.public_key();
    let publication = signer.sign(offer);

    let encoded = CredentialSecretPublicationCodec::encode(&publication);
    assert_ne!(public_key, [0; 32]);
    assert!(
        CredentialSecretPublicationVerifier::new(public_key, &channel)
            .verify(
                replay,
                CredentialSecretPublicationCodec::decode(&encoded).unwrap()
            )
            .is_ok()
    );
    assert_eq!(
        CredentialSecretPublicationCodec::encode(
            &CredentialSecretPublicationCodec::decode(&encoded).unwrap()
        ),
        encoded
    );
}

fn command() -> CredentialBrokerCommand {
    let operation = CredentialOperationId::from_bytes([70; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(1).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    CredentialBrokerCommand::new(
        operation,
        attempt,
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}
