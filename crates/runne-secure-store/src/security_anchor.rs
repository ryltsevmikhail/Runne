use std::fmt;
use zeroize::Zeroizing;

use sha2::{Digest, Sha256};

use crate::SecureStoreError;

pub const MAX_SEALED_TRANSACTION_TAG_BYTES: usize = 80;

#[derive(Clone, Eq, PartialEq)]
pub struct SealedTransactionTag(Vec<u8>);

impl fmt::Debug for SealedTransactionTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealedTransactionTag(REDACTED)")
    }
}

impl SealedTransactionTag {
    #[cfg(feature = "test-support")]
    /// # Errors
    ///
    /// Returns [`SecureStoreError::InvalidSeal`] for empty or oversized bytes.
    pub fn from_test_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, SecureStoreError> {
        Self::new(bytes.into())
    }

    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, SecureStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_SEALED_TRANSACTION_TAG_BYTES {
            return Err(SecureStoreError::InvalidSeal);
        }
        Ok(Self(bytes))
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// # Errors
    ///
    /// Returns [`SecureStoreError::InvalidSeal`] for empty or oversized bytes.
    pub fn from_storage(bytes: Vec<u8>) -> Result<Self, SecureStoreError> {
        Self::new(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAnchorV1 {
    pub profile_identity_digest: [u8; 32],
    pub database_identity: [u8; 32],
    pub generation: u64,
    pub transaction_digest: [u8; 32],
    pub previous_anchor_digest: [u8; 32],
    pub sealed_transaction: SealedTransactionTag,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredSecurityAnchor {
    Missing,
    LegacyGeneration(u64),
    V1(SecurityAnchorV1),
}

impl SecurityAnchorV1 {
    /// # Errors
    ///
    /// Returns [`SecureStoreError::InvalidTransition`] for an invalid root or
    /// transaction component.
    pub fn new(
        profile_identity_digest: [u8; 32],
        database_identity: [u8; 32],
        generation: u64,
        transaction_digest: [u8; 32],
        previous_anchor_digest: [u8; 32],
        sealed_transaction: SealedTransactionTag,
    ) -> Result<Self, SecureStoreError> {
        if profile_identity_digest == [0; 32]
            || database_identity == [0; 32]
            || transaction_digest == [0; 32]
            || generation == 0
        {
            return Err(SecureStoreError::InvalidTransition);
        }
        Ok(Self {
            profile_identity_digest,
            database_identity,
            generation,
            transaction_digest,
            previous_anchor_digest,
            sealed_transaction,
        })
    }

    #[cfg_attr(not(feature = "test-support"), allow(dead_code))]
    pub(crate) fn is_valid(&self) -> bool {
        self.profile_identity_digest != [0; 32]
            && self.database_identity != [0; 32]
            && self.transaction_digest != [0; 32]
            && self.generation != 0
            && !self.sealed_transaction.bytes().is_empty()
            && self.sealed_transaction.bytes().len() <= MAX_SEALED_TRANSACTION_TAG_BYTES
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"runne/security-anchor/v1\0");
        hasher.update(self.profile_identity_digest);
        hasher.update(self.database_identity);
        hasher.update(self.generation.to_be_bytes());
        hasher.update(self.transaction_digest);
        hasher.update(self.previous_anchor_digest);
        hasher.update(self.sealed_transaction.bytes());
        hasher.finalize().into()
    }
}

#[allow(clippy::redundant_pub_crate)]
#[cfg_attr(
    all(not(target_os = "macos"), not(feature = "test-support")),
    allow(dead_code)
)]
pub(crate) trait SecurityProfileLockBackend {
    fn seal(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError>;
    fn verify(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
        seal: &[u8],
    ) -> Result<(), SecureStoreError>;
    fn encrypt_mutation_payload(
        &self,
        _database: [u8; 32],
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }
    fn decrypt_mutation_payload(
        &self,
        _database: [u8; 32],
        _aad: &[u8],
        _envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }
    fn supports_mutation_payload_encryption(&self) -> bool {
        false
    }
}

/// An opaque, profile-bound guard retained across the SQLite/security-store CAS.
#[cfg_attr(
    all(not(target_os = "macos"), not(feature = "test-support")),
    allow(dead_code)
)]
pub struct SecurityProfileLock<'a> {
    profile_identity_digest: [u8; 32],
    held: Box<dyn SecurityProfileLockBackend + 'a>,
}

impl<'a> SecurityProfileLock<'a> {
    #[cfg_attr(
        all(not(target_os = "macos"), not(feature = "test-support")),
        allow(dead_code)
    )]
    pub(crate) fn new(
        profile_identity_digest: [u8; 32],
        held: impl SecurityProfileLockBackend + 'a,
    ) -> Self {
        Self {
            profile_identity_digest,
            held: Box::new(held),
        }
    }

    #[cfg_attr(
        all(not(target_os = "macos"), not(feature = "test-support")),
        allow(dead_code)
    )]
    pub(crate) fn matches(&self, profile_identity_digest: [u8; 32]) -> bool {
        self.profile_identity_digest == profile_identity_digest
    }

    #[cfg_attr(
        all(not(target_os = "macos"), not(feature = "test-support")),
        allow(dead_code)
    )]
    pub(crate) fn seal(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError> {
        self.held.seal(database, generation, transaction, previous)
    }
    #[cfg_attr(
        all(not(target_os = "macos"), not(feature = "test-support")),
        allow(dead_code)
    )]
    pub(crate) fn verify(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
        seal: &[u8],
    ) -> Result<(), SecureStoreError> {
        self.held
            .verify(database, generation, transaction, previous, seal)
    }

    /// Encrypts a payload using the profile-bound secure-store key. Unsupported
    /// platform backends fail closed and never return plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot encrypt or the operation fails.
    pub fn encrypt_mutation_payload(
        &self,
        database: [u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SecureStoreError> {
        self.held.encrypt_mutation_payload(database, aad, plaintext)
    }

    /// Authenticates and decrypts a profile-bound mutation payload.
    ///
    /// # Errors
    ///
    /// Returns an error when authentication fails or the backend cannot decrypt.
    pub fn decrypt_mutation_payload(
        &self,
        database: [u8; 32],
        aad: &[u8],
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        self.held.decrypt_mutation_payload(database, aad, envelope)
    }

    /// Whether this backend can encrypt mutation payloads without plaintext fallback.
    #[must_use]
    pub fn supports_mutation_payload_encryption(&self) -> bool {
        self.held.supports_mutation_payload_encryption()
    }
}
