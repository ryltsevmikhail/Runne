//! Authenticated, passphrase-encrypted recovery containers for owner seeds.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{AuthorityError, ProjectOwnerTrustConfigV1, framed_transcript};

pub const BACKUP_SCHEMA: &str = "runne.project-owner.encrypted-key-backup/1";
pub const AAD_DOMAIN: &[u8] = b"runne.project-owner.encrypted-key-backup-aad/1";
const FINGERPRINT_DOMAIN: &[u8] = b"runne.project-owner.key-fingerprint/1";

/// Public, authenticated metadata for a passphrase-encrypted owner seed.
pub struct BackupMetadataV1 {
    pub(crate) repository_id: String,
    pub(crate) key_id: [u8; 32],
    pub(crate) key_epoch: u64,
    pub(crate) key_fingerprint: [u8; 32],
    pub(crate) parameters: BackupParameters,
    pub(crate) salt: Vec<u8>,
    pub(crate) nonce: [u8; 24],
    pub(crate) ciphertext: Vec<u8>,
}

/// Bounded Argon2id work factors accepted by backup version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupParameters {
    /// Argon2 memory cost in KiB.
    pub memory_kib: u32,
    /// Argon2 iteration count.
    pub iterations: u32,
    /// Argon2 parallelism.
    pub parallelism: u32,
}

impl BackupParameters {
    /// Version-1 resource-floor parameters.
    pub const V1_DEFAULT: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    };

    /// Construct only a bounded version-1 KDF parameter set.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidBackupParameters`] outside version-1 bounds.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, AuthorityError> {
        let parameters = Self {
            memory_kib,
            iterations,
            parallelism,
        };
        parameters.validate()?;
        Ok(parameters)
    }

    /// Validate KDF floors and ceilings before any expensive work.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidBackupParameters`] outside version-1 bounds.
    pub fn validate(self) -> Result<(), AuthorityError> {
        if !(65_536..=262_144).contains(&self.memory_kib)
            || !(3..=10).contains(&self.iterations)
            || !(1..=4).contains(&self.parallelism)
        {
            return Err(AuthorityError::InvalidBackupParameters);
        }
        Ok(())
    }
}

impl Default for BackupParameters {
    fn default() -> Self {
        Self::V1_DEFAULT
    }
}

/// A passphrase supplied by a caller-owned hidden-input boundary.
pub struct BackupPassphrase(Zeroizing<Vec<u8>>);

impl BackupPassphrase {
    /// Consume an already protected passphrase buffer.
    #[must_use]
    pub const fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

/// Source of unpredictable salt and nonce bytes, injected by the caller.
pub trait BackupRng {
    /// Fill `bytes` from a cryptographically secure source or fail closed.
    ///
    /// # Errors
    ///
    /// Returns a caller-defined failure when secure randomness is unavailable.
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), AuthorityError>;
}

/// Compute the fixed-domain public key fingerprint carried by a backup.
#[must_use]
pub fn key_fingerprint(public_key: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(FINGERPRINT_DOMAIN);
    digest.update(public_key);
    digest.finalize().into()
}

/// Encrypt one owner seed into canonical public metadata.
///
/// # Errors
///
/// Rejects an invalid trust binding or KDF set and never falls back when RNG fails.
pub fn encrypt_backup(
    mut seed: Zeroizing<[u8; 32]>,
    passphrase: BackupPassphrase,
    expected_trust: &ProjectOwnerTrustConfigV1,
    parameters: BackupParameters,
    rng: &mut dyn BackupRng,
) -> Result<BackupMetadataV1, AuthorityError> {
    crate::backup_validation::validate_trust(expected_trust)?;
    parameters.validate()?;
    if SigningKey::from_bytes(&seed).verifying_key().to_bytes() != expected_trust.public_key {
        return Err(AuthorityError::InvalidBackupBinding);
    }
    let mut salt = vec![0_u8; 16];
    let mut nonce = [0_u8; 24];
    rng.fill_bytes(&mut salt)?;
    rng.fill_bytes(&mut nonce)?;
    let mut metadata = BackupMetadataV1 {
        repository_id: expected_trust.repository_id.clone(),
        key_id: expected_trust.key_id,
        key_epoch: expected_trust.epoch,
        key_fingerprint: key_fingerprint(&expected_trust.public_key),
        parameters,
        salt,
        nonce,
        ciphertext: Vec::new(),
    };
    let key = derive_key(passphrase, &metadata)?;
    let aad = metadata.authenticated_data()?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let mut plaintext = Zeroizing::new(vec![0_u8; seed.len()]);
    plaintext.copy_from_slice(seed.as_ref());
    seed.zeroize();
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&metadata.nonce), &aad, &mut plaintext)
        .map_err(|_| AuthorityError::BackupTamperedOrWrongPassphrase)?;
    plaintext.extend_from_slice(&tag);
    metadata.ciphertext = plaintext.to_vec();
    Ok(metadata)
}

/// Decrypt a canonical backup only for its exact expected public trust binding.
///
/// # Errors
///
/// Authentication and passphrase failures always map to one non-secret error code.
pub fn decrypt_backup(
    metadata: &BackupMetadataV1,
    passphrase: BackupPassphrase,
    expected_trust: &ProjectOwnerTrustConfigV1,
) -> Result<Zeroizing<[u8; 32]>, AuthorityError> {
    crate::backup_validation::validate_metadata(metadata)?;
    crate::backup_validation::validate_expected_binding(metadata, expected_trust)?;
    let key = derive_key(passphrase, metadata)?;
    let aad = metadata.authenticated_data()?;
    let (seed, tag) = metadata.ciphertext.split_at(32);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let mut plaintext = Zeroizing::new(seed.to_vec());
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&metadata.nonce),
            &aad,
            &mut plaintext,
            tag.into(),
        )
        .map_err(|_| AuthorityError::BackupTamperedOrWrongPassphrase)?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&plaintext);
    if SigningKey::from_bytes(&seed).verifying_key().to_bytes() != expected_trust.public_key {
        return Err(AuthorityError::BackupTamperedOrWrongPassphrase);
    }
    Ok(seed)
}

impl BackupMetadataV1 {
    /// Return the repository bound into this public backup container.
    #[must_use]
    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    /// Return the public project-owner key identifier bound into this backup.
    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    /// Return the public owner key epoch bound into this backup.
    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    /// Return the fixed-domain fingerprint of the expected public key.
    #[must_use]
    pub const fn key_fingerprint(&self) -> [u8; 32] {
        self.key_fingerprint
    }

    /// Return the bounded KDF parameters authenticated by this backup.
    #[must_use]
    pub const fn parameters(&self) -> BackupParameters {
        self.parameters
    }

    /// Parse only exact canonical version-1 JSON with no duplicate or unknown fields.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidBackupMetadata`] for malformed, noncanonical, or
    /// structurally invalid public metadata.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorityError> {
        crate::backup_codec::parse(bytes)
    }

    /// Return the exact canonical version-1 JSON bytes, including one final LF.
    ///
    /// # Errors
    ///
    /// Returns an error only when canonical serialization cannot be produced.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, AuthorityError> {
        crate::backup_codec::canonical(self, true)
    }

    /// Return the exact framed public authenticated data used by version 1.
    ///
    /// # Errors
    ///
    /// Returns an error only when the metadata cannot be canonically serialized.
    pub fn authenticated_data(&self) -> Result<Vec<u8>, AuthorityError> {
        framed_transcript(AAD_DOMAIN, &crate::backup_codec::canonical(self, false)?)
    }
}

fn derive_key(
    passphrase: BackupPassphrase,
    metadata: &BackupMetadataV1,
) -> Result<Zeroizing<[u8; 32]>, AuthorityError> {
    let params = Params::new(
        metadata.parameters.memory_kib,
        metadata.parameters.iterations,
        metadata.parameters.parallelism,
        Some(32),
    )
    .map_err(|_| AuthorityError::InvalidBackupParameters)?;
    let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
    let mut output = Zeroizing::new([0_u8; 32]);
    let BackupPassphrase(passphrase) = passphrase;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(
            &passphrase,
            &metadata.salt,
            &mut *output,
            memory.as_mut_slice(),
        )
        .map_err(|_| AuthorityError::InvalidBackupParameters)?;
    Ok(output)
}
