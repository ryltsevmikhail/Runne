use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    hkdf,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationId,
    CredentialTicketAttempt,
};

pub(super) const SECRET_VERSION: u8 = 1;
const OFFER_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_SECRET_OFFER_V1\0";
const AAD_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_SECRET_AAD_V1\0";
const KEY_LABEL: &[u8] = b"GOCODE_CREDENTIAL_SECRET_KEY_V1\0";
const NONCE_LABEL: &[u8] = b"GOCODE_CREDENTIAL_SECRET_NONCE_V1\0";
const TAG_BYTES: usize = 16;

pub(super) struct CipherTranscript {
    pub(super) operation: CredentialOperationId,
    pub(super) attempt: CredentialTicketAttempt,
    pub(super) claim: CredentialBindingDigest,
    pub(super) offer: CredentialBindingDigest,
    pub(super) writer: [u8; 32],
    pub(super) sealer: [u8; 32],
    pub(super) length: u16,
}

pub(super) fn offer_binding(
    operation_id: CredentialOperationId,
    attempt: CredentialTicketAttempt,
    claim: CredentialBindingDigest,
    writer: [u8; 32],
) -> CredentialBindingDigest {
    let mut hasher = Sha256::new();
    hasher.update(OFFER_DOMAIN);
    hasher.update(operation_id.as_bytes());
    hasher.update(attempt.get().to_be_bytes());
    hasher.update(claim.as_bytes());
    hasher.update(writer);
    CredentialBindingDigest::from_measured(hasher.finalize().into()).expect("SHA-256 is non-zero")
}

pub(super) fn seal(
    shared: &[u8],
    transcript: &CipherTranscript,
    mut credential: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, CredentialEnrollmentError> {
    let aad = aad(transcript);
    let (key_bytes, nonce) = derive(shared, transcript.offer, &aad)?;
    let key = key(&*key_bytes)?;
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad.as_slice()),
            &mut credential,
        )
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?;
    credential.extend_from_slice(tag.as_ref());
    Ok(credential)
}

pub(super) fn open(
    shared: &[u8],
    transcript: &CipherTranscript,
    mut ciphertext: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, CredentialEnrollmentError> {
    if ciphertext.len() != usize::from(transcript.length) + TAG_BYTES {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    let aad = aad(transcript);
    let (key_bytes, nonce) = derive(shared, transcript.offer, &aad)?;
    let length = key(&*key_bytes)?
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad.as_slice()),
            &mut ciphertext,
        )
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?
        .len();
    ciphertext.truncate(length);
    Ok(ciphertext)
}

pub(super) fn validate_credential(
    credential: &[u8],
    kind: super::crypto::CredentialSecretEnvelopeKind,
) -> Result<(), CredentialEnrollmentError> {
    let max = match kind {
        super::crypto::CredentialSecretEnvelopeKind::Legacy => 4096,
        super::crypto::CredentialSecretEnvelopeKind::NativeOAuth => 32 * 1024,
    };
    if credential.is_empty()
        || credential.len() > max
        || credential
            .iter()
            .any(|byte| matches!(byte, b'\n' | b'\r' | 0))
    {
        return Err(CredentialEnrollmentError::InvalidInput);
    }
    Ok(())
}

fn key(bytes: &[u8]) -> Result<LessSafeKey, CredentialEnrollmentError> {
    UnboundKey::new(&aead::CHACHA20_POLY1305, bytes)
        .map(LessSafeKey::new)
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)
}

fn aad(transcript: &CipherTranscript) -> Vec<u8> {
    [
        AAD_DOMAIN,
        &[SECRET_VERSION],
        &transcript.operation.as_bytes(),
        &transcript.attempt.get().to_be_bytes(),
        &transcript.claim.as_bytes(),
        &transcript.offer.as_bytes(),
        &transcript.writer,
        &transcript.sealer,
        &transcript.length.to_be_bytes(),
    ]
    .concat()
}

type DerivedKey = Zeroizing<[u8; 32]>;
type DerivedNonce = Zeroizing<[u8; 12]>;
type DerivedMaterial = (DerivedKey, DerivedNonce);

fn derive(
    shared: &[u8],
    offer: CredentialBindingDigest,
    aad: &[u8],
) -> Result<DerivedMaterial, CredentialEnrollmentError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &offer.as_bytes()).extract(shared);
    let mut key = Zeroizing::new([0; 32]);
    prk.expand(&[KEY_LABEL, aad], HkdfLength(32))
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?
        .fill(&mut *key)
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?;
    let mut nonce = Zeroizing::new([0; 12]);
    prk.expand(&[NONCE_LABEL, aad], HkdfLength(12))
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?
        .fill(&mut *nonce)
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?;
    Ok((key, nonce))
}

struct HkdfLength(usize);

impl hkdf::KeyType for HkdfLength {
    fn len(&self) -> usize {
        self.0
    }
}
