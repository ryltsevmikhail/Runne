use zeroize::Zeroizing;

use crate::credential::enrollment::{CredentialBindingDigest, CredentialEnrollmentError};

use super::{
    CredentialSecretOfferCodec, CredentialSecretPublicationCodec, SealedCredentialEnvelope,
    publication::CredentialSecretPublicationVerifier,
};

const MAGIC: &[u8; 8] = b"GCSREL01";
const HEADER_BYTES: usize = MAGIC.len() + 1;

/// Exact non-secret daemon-to-host relay frame.
pub struct CredentialSecretRelayFrameCodec;

impl CredentialSecretRelayFrameCodec {
    /// Exact byte length of one offer/publication relay frame.
    pub const BYTES: usize =
        HEADER_BYTES + CredentialSecretOfferCodec::BYTES + CredentialSecretPublicationCodec::BYTES;

    /// Encodes the exact writer offer and daemon-signed publication together.
    #[must_use]
    pub fn encode(
        offer: &super::CredentialSecretClaimOffer,
        publication: &super::CredentialSecretPublication,
    ) -> [u8; Self::BYTES] {
        let mut output = [0; Self::BYTES];
        output[..8].copy_from_slice(MAGIC);
        output[8] = 1;
        let offer_end = HEADER_BYTES + CredentialSecretOfferCodec::BYTES;
        output[HEADER_BYTES..offer_end].copy_from_slice(&CredentialSecretOfferCodec::encode(offer));
        output[offer_end..].copy_from_slice(&CredentialSecretPublicationCodec::encode(publication));
        output
    }
}

/// One-shot seal authority bound to an already authenticated rendezvous.
///
/// Construction exposes no low-level publication verifier and sealing consumes
/// the value, so one protected relay cannot authorize a second fd3 write.
pub struct AuthenticatedCredentialSecretRelaySealer {
    daemon_public_key: [u8; 32],
    channel: CredentialBindingDigest,
}

impl AuthenticatedCredentialSecretRelaySealer {
    /// Binds the internal facade to facts authenticated by the native rendezvous owner.
    #[doc(hidden)]
    pub fn from_authenticated_rendezvous(
        daemon_public_key: [u8; 32],
        channel_binding: [u8; 32],
    ) -> Result<Self, CredentialEnrollmentError> {
        if daemon_public_key == [0; 32] {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            daemon_public_key,
            channel: CredentialBindingDigest::from_measured(channel_binding)?,
        })
    }

    /// Verifies the exact signed offer and consumes plaintext only into one envelope.
    pub fn seal(
        self,
        frame: &[u8],
        credential: Zeroizing<Vec<u8>>,
    ) -> Result<SealedCredentialEnvelope, CredentialEnrollmentError> {
        if frame.len() != CredentialSecretRelayFrameCodec::BYTES
            || frame[..8] != *MAGIC
            || frame[8] != 1
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let offer_end = HEADER_BYTES + CredentialSecretOfferCodec::BYTES;
        let offer = CredentialSecretOfferCodec::decode(&frame[HEADER_BYTES..offer_end])?;
        let publication = CredentialSecretPublicationCodec::decode(&frame[offer_end..])?;
        CredentialSecretPublicationVerifier::from_authenticated_digest(
            self.daemon_public_key,
            self.channel,
        )
        .verify(offer, publication)?
        .seal(credential)
    }
}

impl core::fmt::Debug for AuthenticatedCredentialSecretRelaySealer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedCredentialSecretRelaySealer(<one-shot>)")
    }
}
