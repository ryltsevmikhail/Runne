use ring::signature;

use crate::credential::enrollment::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialEnrollmentError,
    CredentialOperationId, CredentialTicketAttempt,
};

use super::CredentialSecretClaimOffer;

const DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_SECRET_PUBLICATION_V1\0";
const VERSION: u8 = 1;
const SEQUENCE: u64 = 1;
const BYTES: usize = 257;

/// Inert fixed-width daemon publication; decoding it grants no seal authority.
pub struct CredentialSecretPublication {
    operation: CredentialOperationId,
    attempt: CredentialTicketAttempt,
    claim: CredentialBindingDigest,
    offer: CredentialBindingDigest,
    writer: [u8; 32],
    channel: CredentialBindingDigest,
    daemon_public_key: [u8; 32],
    signature: [u8; 64],
}

/// Post-attestation one-shot signer for one exact secret publication.
pub struct CredentialSecretPublicationSigner {
    key_pair: signature::Ed25519KeyPair,
    channel: CredentialBindingDigest,
    operation: CredentialOperationId,
    attempt: CredentialTicketAttempt,
    claim: CredentialBindingDigest,
}

impl CredentialSecretPublicationSigner {
    pub(in crate::credential::enrollment::protocol) const fn after_attestation(
        key_pair: signature::Ed25519KeyPair,
        channel: CredentialBindingDigest,
        operation: CredentialOperationId,
        attempt: CredentialTicketAttempt,
        claim: CredentialBindingDigest,
    ) -> Self {
        Self {
            key_pair,
            channel,
            operation,
            attempt,
            claim,
        }
    }

    /// Returns only the shared session/publication public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        use ring::signature::KeyPair as _;
        self.key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("ed25519 key width")
    }

    /// Signs only the exact attested operation, attempt, claim, and channel.
    pub fn sign(
        self,
        offer: CredentialSecretClaimOffer,
        channel: CredentialBindingDigest,
    ) -> Result<CredentialSecretPublication, CredentialEnrollmentError> {
        if offer.operation_id != self.operation
            || offer.attempt != self.attempt
            || offer.claim_binding != self.claim
            || channel != self.channel
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let daemon_public_key = self.public_key();
        let signature = self.key_pair.sign(&message(
            offer.operation_id,
            offer.attempt,
            offer.claim_binding,
            offer.offer_binding,
            offer.writer_public_key,
            self.channel,
            daemon_public_key,
        ));
        Ok(CredentialSecretPublication {
            operation: offer.operation_id,
            attempt: offer.attempt,
            claim: offer.claim_binding,
            offer: offer.offer_binding,
            writer: offer.writer_public_key,
            channel: self.channel,
            daemon_public_key,
            signature: signature
                .as_ref()
                .try_into()
                .expect("ed25519 signature width"),
        })
    }
}

/// Verifies publications from one authenticated rendezvous public key and channel.
pub(crate) struct CredentialSecretPublicationVerifier {
    daemon_public_key: [u8; 32],
    channel: CredentialBindingDigest,
}

/// The only credential offer allowed to seal plaintext after verified publication.
pub(crate) struct VerifiedCredentialSecretOffer {
    pub(crate) offer: CredentialSecretClaimOffer,
}

/// Exact codec for fixed signed credential publications.
pub struct CredentialSecretPublicationCodec;

impl CredentialSecretPublicationVerifier {
    /// Binds verification to the authenticated daemon key and live rendezvous channel.
    #[must_use]
    pub(crate) fn new(daemon_public_key: [u8; 32], channel: &BrokerChannelBinding) -> Self {
        Self::from_authenticated_digest(daemon_public_key, channel.digest())
    }

    pub(super) const fn from_authenticated_digest(
        daemon_public_key: [u8; 32],
        channel: CredentialBindingDigest,
    ) -> Self {
        Self {
            daemon_public_key,
            channel,
        }
    }

    /// Verifies the exact signed publication before creating a seal-capable offer.
    pub(crate) fn verify(
        self,
        offer: CredentialSecretClaimOffer,
        publication: CredentialSecretPublication,
    ) -> Result<VerifiedCredentialSecretOffer, CredentialEnrollmentError> {
        if publication.operation != offer.operation_id
            || publication.attempt != offer.attempt
            || publication.claim != offer.claim_binding
            || publication.offer != offer.offer_binding
            || publication.writer != offer.writer_public_key
            || publication.channel != self.channel
            || publication.daemon_public_key != self.daemon_public_key
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let message = message(
            publication.operation,
            publication.attempt,
            publication.claim,
            publication.offer,
            publication.writer,
            publication.channel,
            publication.daemon_public_key,
        );
        signature::UnparsedPublicKey::new(&signature::ED25519, self.daemon_public_key)
            .verify(&message, &publication.signature)
            .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?;
        Ok(VerifiedCredentialSecretOffer { offer })
    }
}

#[cfg(feature = "test-support")]
pub(crate) fn verify_for_test(
    daemon_public_key: [u8; 32],
    channel_binding: [u8; 32],
    offer: CredentialSecretClaimOffer,
    publication: CredentialSecretPublication,
) -> Result<(), CredentialEnrollmentError> {
    let channel = CredentialBindingDigest::from_measured(channel_binding)?;
    CredentialSecretPublicationVerifier {
        daemon_public_key,
        channel,
    }
    .verify(offer, publication)
    .map(|_| ())
}

impl CredentialSecretPublicationCodec {
    /// Exact byte length of a signed publication.
    pub const BYTES: usize = BYTES;
    /// Encodes one publication in its sole fixed-width form.
    #[must_use]
    pub fn encode(value: &CredentialSecretPublication) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[0] = VERSION;
        bytes[1..17].copy_from_slice(&value.operation.as_bytes());
        bytes[17..25].copy_from_slice(&value.attempt.get().to_be_bytes());
        bytes[25..57].copy_from_slice(&value.claim.as_bytes());
        bytes[57..89].copy_from_slice(&value.offer.as_bytes());
        bytes[89..121].copy_from_slice(&value.writer);
        bytes[121..153].copy_from_slice(&value.channel.as_bytes());
        bytes[153..185].copy_from_slice(&value.daemon_public_key);
        bytes[185..193].copy_from_slice(&SEQUENCE.to_be_bytes());
        bytes[193..].copy_from_slice(&value.signature);
        bytes
    }
    /// Decodes an inert publication only when its exact fixed layout is valid.
    pub fn decode(bytes: &[u8]) -> Result<CredentialSecretPublication, CredentialEnrollmentError> {
        if bytes.len() != BYTES || bytes[0] != VERSION || bytes[185..193] != SEQUENCE.to_be_bytes()
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Ok(CredentialSecretPublication {
            operation: CredentialOperationId::from_bytes(fixed(bytes, 1)?)
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
            attempt: CredentialTicketAttempt::new(u64::from_be_bytes(fixed(bytes, 17)?))
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
            claim: digest(fixed(bytes, 25)?)?,
            offer: digest(fixed(bytes, 57)?)?,
            writer: fixed(bytes, 89)?,
            channel: digest(fixed(bytes, 121)?)?,
            daemon_public_key: fixed(bytes, 153)?,
            signature: fixed(bytes, 193)?,
        })
    }
}

fn message(
    operation: CredentialOperationId,
    attempt: CredentialTicketAttempt,
    claim: CredentialBindingDigest,
    offer: CredentialBindingDigest,
    writer: [u8; 32],
    channel: CredentialBindingDigest,
    daemon: [u8; 32],
) -> Vec<u8> {
    [
        DOMAIN,
        &[VERSION],
        &operation.as_bytes(),
        &attempt.get().to_be_bytes(),
        &claim.as_bytes(),
        &offer.as_bytes(),
        &writer,
        &channel.as_bytes(),
        &daemon,
        &SEQUENCE.to_be_bytes(),
    ]
    .concat()
}
fn digest(value: [u8; 32]) -> Result<CredentialBindingDigest, CredentialEnrollmentError> {
    CredentialBindingDigest::from_measured(value)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}
fn fixed<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], CredentialEnrollmentError> {
    bytes
        .get(offset..offset + N)
        .ok_or(CredentialEnrollmentError::InvalidFrame)?
        .try_into()
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}

#[cfg(test)]
pub(super) fn fixture_publication(
    offer: &CredentialSecretClaimOffer,
    channel: &BrokerChannelBinding,
) -> ([u8; 32], CredentialSecretPublication) {
    use ring::signature::KeyPair;
    let key = signature::Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    let daemon_public_key = key.public_key().as_ref().try_into().unwrap();
    let signature = key
        .sign(&message(
            offer.operation_id,
            offer.attempt,
            offer.claim_binding,
            offer.offer_binding,
            offer.writer_public_key,
            channel.digest(),
            daemon_public_key,
        ))
        .as_ref()
        .try_into()
        .unwrap();
    (
        daemon_public_key,
        CredentialSecretPublication {
            operation: offer.operation_id,
            attempt: offer.attempt,
            claim: offer.claim_binding,
            offer: offer.offer_binding,
            writer: offer.writer_public_key,
            channel: channel.digest(),
            daemon_public_key,
            signature,
        },
    )
}
