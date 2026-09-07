use ring::signature;
use sha2::{Digest as _, Sha256};

use super::claims::SignedCredentialWriterSessionAttestationV2;
use crate::credential::enrollment::CredentialEnrollmentError;

const MAGIC: &[u8; 8] = b"RNQWPRE1";
const DOMAIN: &[u8] = b"GOCODE_PROVIDER_CREDENTIAL_WRITER_QUALIFICATION_PRELUDE_V1\0";
const VERSION: u8 = 1;
const SEQUENCE: u64 = 1;
const HEADER_BYTES: usize = 53;
const SIGNATURE_BYTES: usize = 64;
const MAX_BUNDLE_BYTES: usize = 8192;
const MAX_CONTEXT_BYTES: usize = 2048;
const MAX_TICKET_BYTES: usize = 4096;

/// Signed daemon-to-writer commitment carrying the admitted context bundle.
pub struct CredentialWriterQualifiedPreludeV1 {
    pub(crate) attestation_digest: [u8; 32],
    pub(crate) bundle: Vec<u8>,
    pub(crate) signature: [u8; 64],
}

impl CredentialWriterQualifiedPreludeV1 {
    /// Digest of the complete canonical prelude, including its signature.
    #[must_use]
    pub fn full_digest(&self) -> [u8; 32] {
        Sha256::digest(CredentialWriterQualifiedPreludeCodec::encode(self).unwrap()).into()
    }

    /// Returns the committed complete V2 attestation digest.
    #[must_use]
    pub const fn attestation_digest(&self) -> [u8; 32] {
        self.attestation_digest
    }

    /// Checks the attestation digest and the exact semantic RNQADM1 members.
    #[must_use]
    pub fn matches_attestation(
        &self,
        attestation: &SignedCredentialWriterSessionAttestationV2,
    ) -> bool {
        if self.attestation_digest != attestation.full_digest()
            || bundle_bounds(&self.bundle).is_err()
        {
            return false;
        }
        if self.bundle.len() < 17
            || self.bundle.get(..8) != Some(b"RNQADM1\0".as_slice())
            || self.bundle[8] != 1
        {
            return false;
        }
        let context_len = match self.bundle[9..13].try_into() {
            Ok(bytes) => u32::from_be_bytes(bytes) as usize,
            Err(_) => return false,
        };
        let ticket_len = match self.bundle[13..17].try_into() {
            Ok(bytes) => u32::from_be_bytes(bytes) as usize,
            Err(_) => return false,
        };
        let context_end = match 17usize.checked_add(context_len) {
            Some(value) => value,
            None => return false,
        };
        let Some(ticket_end) = context_end.checked_add(ticket_len) else {
            return false;
        };
        let (Some(context), Some(ticket)) = (
            self.bundle.get(17..context_end),
            self.bundle.get(context_end..ticket_end),
        ) else {
            return false;
        };
        ticket_end == self.bundle.len()
            && Sha256::digest(context).as_slice() == attestation.context_sha256()
            && Sha256::digest(ticket).as_slice() == attestation.ticket_sha256()
    }
}

/// Exact codec for the bounded qualification prelude.
pub struct CredentialWriterQualifiedPreludeCodec;

impl CredentialWriterQualifiedPreludeCodec {
    /// Encodes one exact prelude after checking its member bound.
    pub fn encode(
        value: &CredentialWriterQualifiedPreludeV1,
    ) -> Result<Vec<u8>, CredentialEnrollmentError> {
        bundle_bounds(&value.bundle)?;
        let mut bytes = Vec::with_capacity(HEADER_BYTES + value.bundle.len() + SIGNATURE_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&SEQUENCE.to_be_bytes());
        bytes.extend_from_slice(&value.attestation_digest);
        bytes.extend_from_slice(&(value.bundle.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&value.bundle);
        bytes.extend_from_slice(&value.signature);
        Ok(bytes)
    }

    /// Decodes and verifies the exact prelude against the authenticated daemon key.
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_public_key: [u8; 32],
    ) -> Result<CredentialWriterQualifiedPreludeV1, CredentialEnrollmentError> {
        if bytes.len() < HEADER_BYTES + SIGNATURE_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes[8] != VERSION
            || bytes[9..17] != SEQUENCE.to_be_bytes()
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let length = usize::try_from(u32::from_be_bytes(
            bytes[49..53]
                .try_into()
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
        ))
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        let total = HEADER_BYTES
            .checked_add(length)
            .and_then(|value| value.checked_add(SIGNATURE_BYTES))
            .ok_or(CredentialEnrollmentError::InvalidFrame)?;
        if !(1..=MAX_BUNDLE_BYTES).contains(&length) || bytes.len() != total {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        bundle_bounds(&bytes[HEADER_BYTES..HEADER_BYTES + length])?;
        if expected_public_key == [0; 32] {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        signature::UnparsedPublicKey::new(&signature::ED25519, expected_public_key)
            .verify(
                &[DOMAIN, &bytes[..bytes.len() - SIGNATURE_BYTES]].concat(),
                &bytes[bytes.len() - SIGNATURE_BYTES..],
            )
            .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?;
        Ok(CredentialWriterQualifiedPreludeV1 {
            attestation_digest: bytes[17..49]
                .try_into()
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
            bundle: bytes[HEADER_BYTES..HEADER_BYTES + length].to_vec(),
            signature: bytes[bytes.len() - SIGNATURE_BYTES..]
                .try_into()
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
        })
    }

    /// Reads one bounded variable-length prelude without consuming a following phase.
    pub fn read_from<R: std::io::Read>(
        reader: &mut R,
        expected_public_key: [u8; 32],
    ) -> Result<CredentialWriterQualifiedPreludeV1, CredentialEnrollmentError> {
        let mut header = [0; HEADER_BYTES];
        reader
            .read_exact(&mut header)
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        if header[..8] != *MAGIC || header[8] != VERSION || header[9..17] != SEQUENCE.to_be_bytes()
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let length = usize::try_from(u32::from_be_bytes(
            header[49..53]
                .try_into()
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
        ))
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        if !(1..=MAX_BUNDLE_BYTES).contains(&length) {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let mut bytes = Vec::with_capacity(HEADER_BYTES + length + SIGNATURE_BYTES);
        bytes.extend_from_slice(&header);
        let mut tail = vec![0; length + SIGNATURE_BYTES];
        reader
            .read_exact(&mut tail)
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        bytes.extend_from_slice(&tail);
        Self::decode_and_verify(&bytes, expected_public_key)
    }

    pub(crate) fn sign(
        key_pair: &signature::Ed25519KeyPair,
        attestation_digest: [u8; 32],
        bundle: Vec<u8>,
    ) -> Result<CredentialWriterQualifiedPreludeV1, CredentialEnrollmentError> {
        let unsigned = CredentialWriterQualifiedPreludeV1 {
            attestation_digest,
            bundle,
            signature: [0; 64],
        };
        let bytes = Self::encode(&unsigned)?;
        let signature = key_pair.sign(&[DOMAIN, &bytes[..bytes.len() - SIGNATURE_BYTES]].concat());
        Ok(CredentialWriterQualifiedPreludeV1 {
            signature: signature.as_ref().try_into().expect("signature width"),
            ..unsigned
        })
    }
}

fn bundle_bounds(bundle: &[u8]) -> Result<(), CredentialEnrollmentError> {
    if bundle.len() < 17 || bundle.get(..8) != Some(b"RNQADM1\0".as_slice()) || bundle[8] != 1 {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    let context_len = usize::try_from(u32::from_be_bytes(
        bundle[9..13]
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    ))
    .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let ticket_len = usize::try_from(u32::from_be_bytes(
        bundle[13..17]
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    ))
    .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    if !(1..=MAX_CONTEXT_BYTES).contains(&context_len)
        || !(1..=MAX_TICKET_BYTES).contains(&ticket_len)
    {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    let total = 17usize
        .checked_add(context_len)
        .and_then(|value| value.checked_add(ticket_len))
        .ok_or(CredentialEnrollmentError::InvalidFrame)?;
    if total != bundle.len() || total > MAX_BUNDLE_BYTES {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    Ok(())
}
