//! Private seal implementation reachable only from an authenticated handoff.

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use ring::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey},
    agreement, hkdf,
    rand::SystemRandom,
};
use zeroize::Zeroizing;

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::daemon_rendezvous::AuthenticatedPairSecretHandoff;

const RELAY_MAGIC: &[u8; 8] = b"GCSREL01";
const RELAY_HEADER: usize = 9;
const OFFER_BYTES: usize = runne_provider::CredentialSecretOfferCodec::BYTES;
const PUBLICATION_BYTES: usize = runne_provider::CredentialSecretPublicationCodec::BYTES;
const PUBLICATION_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_SECRET_PUBLICATION_V1\0";
const AAD_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_SECRET_AAD_V1\0";
const KEY_LABEL: &[u8] = b"GOCODE_CREDENTIAL_SECRET_KEY_V1\0";
const NONCE_LABEL: &[u8] = b"GOCODE_CREDENTIAL_SECRET_NONCE_V1\0";

pub struct AuthenticatedPairSecretSealer {
    handoff: AuthenticatedPairSecretHandoff,
}

impl AuthenticatedPairSecretSealer {
    #[cfg(target_os = "linux")]
    pub(super) const fn into_public_context(self) -> ([u8; 32], [u8; 32]) {
        let (publication_key, channel_binding) = self.handoff.into_relay_facts();
        (channel_binding, publication_key)
    }

    #[cfg(target_os = "linux")]
    pub(super) const fn from_verified_public_context(
        channel_binding: [u8; 32],
        publication_public_key: [u8; 32],
    ) -> Self {
        Self::from_handoff(AuthenticatedPairSecretHandoff::from_relay_facts(
            channel_binding,
            publication_public_key,
        ))
    }

    /// Wraps the authenticated handoff into the private sealer; this is the
    /// only construction path and it stays inside the broker module because
    /// the handoff type itself is broker-module-private.
    #[must_use]
    pub(in crate::provider_credential_broker) const fn from_handoff(
        handoff: AuthenticatedPairSecretHandoff,
    ) -> Self {
        Self { handoff }
    }

    pub(super) fn seal(
        self,
        frame: &[u8],
        credential: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, BrokerHandoffError> {
        let transcript = self.verify(frame)?;
        seal_envelope(&transcript, credential, false)
    }

    pub(super) fn seal_native_oauth(
        self,
        frame: &[u8],
        credential: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, BrokerHandoffError> {
        let transcript = self.verify(frame)?;
        seal_envelope(&transcript, credential, true)
    }

    fn verify(self, frame: &[u8]) -> Result<OfferTranscript, BrokerHandoffError> {
        let (daemon_public_key, channel) = self.handoff.into_relay_facts();
        if frame.len() != RELAY_HEADER + OFFER_BYTES + PUBLICATION_BYTES
            || frame[..8] != *RELAY_MAGIC
            || frame[8] != 1
        {
            return Err(BrokerHandoffError::Rejected);
        }
        let offer = &frame[RELAY_HEADER..RELAY_HEADER + OFFER_BYTES];
        let publication = &frame[RELAY_HEADER + OFFER_BYTES..];
        runne_provider::CredentialSecretOfferCodec::decode(offer)
            .map_err(|_| BrokerHandoffError::Rejected)?;
        runne_provider::CredentialSecretPublicationCodec::decode(publication)
            .map_err(|_| BrokerHandoffError::Rejected)?;
        let transcript = OfferTranscript::parse(offer)?;
        if publication[1..57] != offer[2..58]
            || publication[57..89] != offer[90..122]
            || publication[89..121] != offer[58..90]
            || publication[121..153] != channel
            || publication[153..185] != daemon_public_key
        {
            return Err(BrokerHandoffError::Rejected);
        }
        let message = publication_message(publication);
        let key = VerifyingKey::from_bytes(&daemon_public_key)
            .map_err(|_| BrokerHandoffError::Rejected)?;
        let signature =
            Signature::from_slice(&publication[193..]).map_err(|_| BrokerHandoffError::Rejected)?;
        key.verify(&message, &signature)
            .map_err(|_| BrokerHandoffError::Rejected)?;
        Ok(transcript)
    }
}

struct OfferTranscript {
    operation: [u8; 16],
    attempt: [u8; 8],
    claim: [u8; 32],
    writer: [u8; 32],
    offer: [u8; 32],
}

impl OfferTranscript {
    fn parse(bytes: &[u8]) -> Result<Self, BrokerHandoffError> {
        Ok(Self {
            operation: fixed(bytes, 2)?,
            attempt: fixed(bytes, 18)?,
            claim: fixed(bytes, 26)?,
            writer: fixed(bytes, 58)?,
            offer: fixed(bytes, 90)?,
        })
    }
}

fn publication_message(bytes: &[u8]) -> Vec<u8> {
    [
        PUBLICATION_DOMAIN,
        &bytes[..1],
        &bytes[1..185],
        &bytes[185..193],
    ]
    .concat()
}

fn seal_envelope(
    transcript: &OfferTranscript,
    mut credential: Zeroizing<Vec<u8>>,
    native_oauth: bool,
) -> Result<Zeroizing<Vec<u8>>, BrokerHandoffError> {
    let max = if native_oauth { 32 * 1024 } else { 4096 };
    if credential.is_empty()
        || credential.len() > max
        || credential
            .iter()
            .any(|byte| matches!(byte, b'\n' | b'\r' | 0))
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let length = u16::try_from(credential.len()).map_err(|_| BrokerHandoffError::Rejected)?;
    let private =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())
            .map_err(|_| BrokerHandoffError::Unavailable)?;
    let sealer: [u8; 32] = private
        .compute_public_key()
        .map_err(|_| BrokerHandoffError::Unavailable)?
        .as_ref()
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let aad = aad(transcript, sealer, length);
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, transcript.writer);
    agreement::agree_ephemeral(private, &peer, |shared| {
        encrypt(shared, transcript.offer, &aad, &mut credential)
    })
    .map_err(|_| BrokerHandoffError::Rejected)??;
    let mut envelope = Zeroizing::new(vec![0; 124 + credential.len()]);
    let version = if native_oauth {
        runne_provider::CredentialSecretEnvelopeCodec::VERSION + 1
    } else {
        runne_provider::CredentialSecretEnvelopeCodec::VERSION
    };
    envelope[..2].copy_from_slice(&[version, 2]);
    envelope[2..18].copy_from_slice(&transcript.operation);
    envelope[18..26].copy_from_slice(&transcript.attempt);
    envelope[26..58].copy_from_slice(&transcript.claim);
    envelope[58..90].copy_from_slice(&transcript.offer);
    envelope[90..122].copy_from_slice(&sealer);
    envelope[122..124].copy_from_slice(&length.to_be_bytes());
    envelope[124..].copy_from_slice(&credential);
    runne_provider::CredentialSecretEnvelopeCodec::decode(&envelope)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    Ok(envelope)
}

fn aad(transcript: &OfferTranscript, sealer: [u8; 32], length: u16) -> Vec<u8> {
    [
        AAD_DOMAIN,
        &[1],
        &transcript.operation,
        &transcript.attempt,
        &transcript.claim,
        &transcript.offer,
        &transcript.writer,
        &sealer,
        &length.to_be_bytes(),
    ]
    .concat()
}

fn encrypt(
    shared: &[u8],
    offer: [u8; 32],
    aad: &[u8],
    credential: &mut Vec<u8>,
) -> Result<(), BrokerHandoffError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &offer);
    let prk = salt.extract(shared);
    let mut key = Zeroizing::new([0; 32]);
    prk.expand(&[KEY_LABEL, aad], HkdfLength(32))
        .map_err(|_| BrokerHandoffError::Rejected)?
        .fill(&mut *key)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let mut nonce = Zeroizing::new([0; 12]);
    prk.expand(&[NONCE_LABEL, aad], HkdfLength(12))
        .map_err(|_| BrokerHandoffError::Rejected)?
        .fill(&mut *nonce)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, &*key).map_err(|_| BrokerHandoffError::Rejected)?,
    );
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            credential,
        )
        .map_err(|_| BrokerHandoffError::Rejected)?;
    credential.extend_from_slice(tag.as_ref());
    Ok(())
}

struct HkdfLength(usize);
impl hkdf::KeyType for HkdfLength {
    fn len(&self) -> usize {
        self.0
    }
}

fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], BrokerHandoffError> {
    bytes
        .get(offset..offset + N)
        .ok_or(BrokerHandoffError::Rejected)?
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)
}

#[cfg(test)]
#[path = "macos_secret_sealer_tests.rs"]
mod tests;
