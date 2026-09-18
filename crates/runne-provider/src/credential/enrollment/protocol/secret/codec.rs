use zeroize::Zeroizing;

use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationId,
    CredentialTicketAttempt,
};

use super::cipher::SECRET_VERSION;
use super::{CredentialSecretClaimOffer, CredentialSecretEnvelopeKind, SealedCredentialEnvelope};

const OFFER_KIND: u8 = 1;
const ENVELOPE_KIND: u8 = 2;
const OFFER_BYTES: usize = 122;
const ENVELOPE_HEADER_BYTES: usize = 124;
const TAG_BYTES: usize = 16;

/// Exact codec for non-secret writer claim offers.
pub struct CredentialSecretOfferCodec;

/// Exact codec for encrypted credential envelopes.
pub struct CredentialSecretEnvelopeCodec;

impl CredentialSecretOfferCodec {
    /// The only supported secret-relay codec version.
    pub const VERSION: u8 = SECRET_VERSION;
    /// Exact fixed byte length of one offer.
    pub const BYTES: usize = OFFER_BYTES;

    /// Encodes one offer in its sole fixed-width representation.
    #[must_use]
    pub fn encode(offer: &CredentialSecretClaimOffer) -> [u8; OFFER_BYTES] {
        let mut bytes = [0; OFFER_BYTES];
        bytes[..2].copy_from_slice(&[Self::VERSION, OFFER_KIND]);
        bytes[2..18].copy_from_slice(&offer.operation_id.as_bytes());
        bytes[18..26].copy_from_slice(&offer.attempt.get().to_be_bytes());
        bytes[26..58].copy_from_slice(&offer.claim_binding.as_bytes());
        bytes[58..90].copy_from_slice(&offer.writer_public_key);
        bytes[90..122].copy_from_slice(&offer.offer_binding.as_bytes());
        bytes
    }

    /// Decodes only one exact validated offer representation.
    pub fn decode(bytes: &[u8]) -> Result<CredentialSecretClaimOffer, CredentialEnrollmentError> {
        if bytes.len() != OFFER_BYTES || bytes[..2] != [Self::VERSION, OFFER_KIND] {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        CredentialSecretClaimOffer::from_decoded(
            operation(bytes, 2)?,
            attempt(bytes, 18)?,
            digest(bytes, 26)?,
            fixed(bytes, 58)?,
            digest(bytes, 90)?,
        )
    }
}

impl CredentialSecretEnvelopeCodec {
    /// The only supported secret-relay codec version.
    pub const VERSION: u8 = SECRET_VERSION;
    /// Largest exact encrypted legacy envelope, for a 4096-byte credential.
    pub const MAX_BYTES: usize = ENVELOPE_HEADER_BYTES + 4096 + TAG_BYTES;
    /// Largest exact encrypted native OAuth envelope, for a 32 KiB payload.
    pub const MAX_NATIVE_OAUTH_BYTES: usize = ENVELOPE_HEADER_BYTES + (32 * 1024) + TAG_BYTES;

    /// Encodes one envelope without exposing its plaintext.
    pub fn encode(
        envelope: &SealedCredentialEnvelope,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialEnrollmentError> {
        if envelope.ciphertext_and_tag.len() != usize::from(envelope.plaintext_len) + TAG_BYTES {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        if envelope.kind != CredentialSecretEnvelopeKind::Legacy {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Self::encode_inner(envelope, super::cipher::SECRET_VERSION)
    }

    /// Encodes one typed native OAuth envelope without widening the legacy codec.
    pub fn encode_native_oauth(
        envelope: &SealedCredentialEnvelope,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialEnrollmentError> {
        if envelope.kind != CredentialSecretEnvelopeKind::NativeOAuth
            || envelope.ciphertext_and_tag.len() != usize::from(envelope.plaintext_len) + TAG_BYTES
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Self::encode_inner(envelope, super::cipher::SECRET_VERSION + 1)
    }

    fn encode_inner(
        envelope: &SealedCredentialEnvelope,
        version: u8,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialEnrollmentError> {
        let mut bytes = Zeroizing::new(vec![
            0;
            ENVELOPE_HEADER_BYTES
                + envelope.ciphertext_and_tag.len()
        ]);
        bytes[..2].copy_from_slice(&[version, ENVELOPE_KIND]);
        bytes[2..18].copy_from_slice(&envelope.operation_id.as_bytes());
        bytes[18..26].copy_from_slice(&envelope.attempt.get().to_be_bytes());
        bytes[26..58].copy_from_slice(&envelope.claim_binding.as_bytes());
        bytes[58..90].copy_from_slice(&envelope.offer_binding.as_bytes());
        bytes[90..122].copy_from_slice(&envelope.sealer_public_key);
        bytes[122..124].copy_from_slice(&envelope.plaintext_len.to_be_bytes());
        bytes[124..].copy_from_slice(&envelope.ciphertext_and_tag);
        Ok(bytes)
    }

    /// Decodes one bounded envelope and rejects all length or trailing variants.
    pub fn decode(bytes: &[u8]) -> Result<SealedCredentialEnvelope, CredentialEnrollmentError> {
        if bytes.len() < ENVELOPE_HEADER_BYTES + TAG_BYTES
            || bytes[..2] == [0, ENVELOPE_KIND]
            || bytes[1] != ENVELOPE_KIND
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let (kind, max_bytes) = match bytes[0] {
            value if value == Self::VERSION => {
                (CredentialSecretEnvelopeKind::Legacy, Self::MAX_BYTES)
            }
            value if value == Self::VERSION + 1 => (
                CredentialSecretEnvelopeKind::NativeOAuth,
                Self::MAX_NATIVE_OAUTH_BYTES,
            ),
            _ => return Err(CredentialEnrollmentError::InvalidFrame),
        };
        if bytes.len() > max_bytes {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let plaintext_len = u16::from_be_bytes(fixed(bytes, 122)?);
        let max_plaintext = match kind {
            CredentialSecretEnvelopeKind::Legacy => 4096,
            CredentialSecretEnvelopeKind::NativeOAuth => 32 * 1024,
        };
        if plaintext_len == 0
            || usize::from(plaintext_len) > max_plaintext
            || bytes.len() != ENVELOPE_HEADER_BYTES + usize::from(plaintext_len) + TAG_BYTES
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Ok(SealedCredentialEnvelope::from_decoded(
            operation(bytes, 2)?,
            attempt(bytes, 18)?,
            digest(bytes, 26)?,
            digest(bytes, 58)?,
            fixed(bytes, 90)?,
            plaintext_len,
            kind,
            Zeroizing::new(bytes[124..].to_vec()),
        ))
    }
}

fn operation(
    bytes: &[u8],
    offset: usize,
) -> Result<CredentialOperationId, CredentialEnrollmentError> {
    CredentialOperationId::from_bytes(fixed(bytes, offset)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}

fn attempt(
    bytes: &[u8],
    offset: usize,
) -> Result<CredentialTicketAttempt, CredentialEnrollmentError> {
    CredentialTicketAttempt::new(u64::from_be_bytes(fixed(bytes, offset)?))
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}

fn digest(
    bytes: &[u8],
    offset: usize,
) -> Result<CredentialBindingDigest, CredentialEnrollmentError> {
    CredentialBindingDigest::from_measured(fixed(bytes, offset)?)
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
