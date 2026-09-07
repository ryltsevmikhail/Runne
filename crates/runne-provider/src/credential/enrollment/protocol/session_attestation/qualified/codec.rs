use ring::signature;

use super::super::codec::decode_body;
use super::claims::SignedCredentialWriterSessionAttestationV2;
use crate::credential::enrollment::CredentialEnrollmentError;

const DOMAIN: &[u8] = b"GOCODE_PROVIDER_CREDENTIAL_WRITER_SESSION_ATTESTATION_V2\0";
const VERSION: u8 = 2;
const SIGNED_BYTES: usize = 651;
const BYTES: usize = 715;

/// Exact codec for the qualification-required Writer attestation.
pub struct CredentialWriterSessionAttestationV2Codec;

impl CredentialWriterSessionAttestationV2Codec {
    /// Exact complete V2 record length.
    pub const BYTES: usize = BYTES;

    /// Digest of the complete canonical record, including its signature.
    #[must_use]
    pub fn full_digest(value: &SignedCredentialWriterSessionAttestationV2) -> [u8; 32] {
        value.full_digest()
    }

    /// Encodes the complete canonical V2 record.
    #[must_use]
    pub fn encode(value: &SignedCredentialWriterSessionAttestationV2) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        let body = super::super::codec::encode_v1_body(
            &value.claims,
            value.channel,
            value.publication_public_key,
        );
        bytes[..577].copy_from_slice(&body);
        bytes[0] = VERSION;
        bytes[577] = 1;
        bytes[578] = 1;
        bytes[579..587].copy_from_slice(&value.launch_generation.to_be_bytes());
        bytes[587..619].copy_from_slice(&value.context_sha256.as_bytes());
        bytes[619..651].copy_from_slice(&value.ticket_sha256.as_bytes());
        bytes[651..].copy_from_slice(&value.signature);
        bytes
    }

    /// Decodes and verifies a V2 record against the authenticated daemon key.
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_public_key: [u8; 32],
    ) -> Result<SignedCredentialWriterSessionAttestationV2, CredentialEnrollmentError> {
        if bytes.len() != BYTES
            || bytes[0] != VERSION
            || bytes[569..577] != 0_u64.to_be_bytes()
            || bytes[577] != 1
            || bytes[578] != 1
            || u64::from_be_bytes(fixed(bytes, 579)?) == 0
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let (claims, channel, publication_public_key) =
            decode_body(&bytes[..577], expected_public_key)?;
        let context_sha256 = digest(fixed(bytes, 587)?)?;
        let ticket_sha256 = digest(fixed(bytes, 619)?)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, expected_public_key)
            .verify(
                &[DOMAIN, &bytes[..SIGNED_BYTES]].concat(),
                &bytes[SIGNED_BYTES..],
            )
            .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?;
        Ok(SignedCredentialWriterSessionAttestationV2 {
            claims,
            channel,
            publication_public_key,
            launch_generation: u64::from_be_bytes(fixed(bytes, 579)?),
            context_sha256,
            ticket_sha256,
            signature: fixed(bytes, SIGNED_BYTES)?,
        })
    }

    /// Reads exactly one complete V2 record.
    pub fn read_from<R: std::io::Read>(
        reader: &mut R,
        expected_public_key: [u8; 32],
    ) -> Result<SignedCredentialWriterSessionAttestationV2, CredentialEnrollmentError> {
        let mut bytes = [0; BYTES];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        Self::decode_and_verify(&bytes, expected_public_key)
    }

    pub(super) fn signature_message(value: &SignedCredentialWriterSessionAttestationV2) -> Vec<u8> {
        let bytes = Self::encode(value);
        [DOMAIN, &bytes[..SIGNED_BYTES]].concat()
    }
    pub(super) fn digest(
        value: [u8; 32],
    ) -> Result<crate::credential::enrollment::CredentialBindingDigest, CredentialEnrollmentError>
    {
        crate::credential::enrollment::CredentialBindingDigest::from_measured(value)
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)
    }
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

fn digest(
    value: [u8; 32],
) -> Result<crate::credential::enrollment::CredentialBindingDigest, CredentialEnrollmentError> {
    CredentialWriterSessionAttestationV2Codec::digest(value)
}
