use core::fmt;

use rand::{RngCore as _, rngs::OsRng};
use zeroize::Zeroizing;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::SecureStoreError;

/// Renderer-safe, non-secret availability of one exact journal key binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderJournalKeyStatus {
    /// The exact key item exists; material has not been read.
    Available,
    /// No item exists for the exact non-secret binding.
    Missing,
    /// The native backend cannot retain provider journal keys.
    Unsupported,
}

#[cfg(test)]
static COPY_ARRAY_CONSTRUCTOR_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Non-secret identity and authority binding for one provider journal key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderJournalKeyRef {
    key_id: [u8; 16],
    version: u64,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
}

impl ProviderJournalKeyRef {
    /// Constructs an exact non-zero key reference.
    ///
    /// # Errors
    ///
    /// Returns [`SecureStoreError::CorruptProviderJournalKey`] when any
    /// identity, version or generation component is zero.
    pub fn new(
        key_id: [u8; 16],
        version: u64,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
    ) -> Result<Self, SecureStoreError> {
        if key_id == [0; 16]
            || version == 0
            || runtime_authority_id == [0; 16]
            || database_generation == 0
        {
            return Err(SecureStoreError::CorruptProviderJournalKey);
        }
        Ok(Self {
            key_id,
            version,
            runtime_authority_id,
            database_generation,
        })
    }

    /// Returns the non-secret key identity.
    #[must_use]
    pub const fn key_id(self) -> [u8; 16] {
        self.key_id
    }

    /// Returns the positive material version.
    #[must_use]
    pub const fn version(self) -> u64 {
        self.version
    }

    /// Returns the bound runtime authority.
    #[must_use]
    pub const fn runtime_authority_id(self) -> [u8; 16] {
        self.runtime_authority_id
    }

    /// Returns the bound authoritative database generation.
    #[must_use]
    pub const fn database_generation(self) -> u64 {
        self.database_generation
    }
}

/// Zeroizing 32-byte provider journal key material.
pub struct ProviderJournalKeyMaterial {
    key_ref: ProviderJournalKeyRef,
    bytes: Zeroizing<[u8; 32]>,
}

impl ProviderJournalKeyMaterial {
    /// Generates fresh, non-zero material for one exact key reference.
    ///
    /// # Errors
    ///
    /// Returns a closed corruption failure if the operating system random
    /// source returns an all-zero value.
    pub fn generate(key_ref: ProviderJournalKeyRef) -> Result<Self, SecureStoreError> {
        let mut bytes = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| SecureStoreError::ProviderJournalKeyGenerationFailed)?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(SecureStoreError::CorruptProviderJournalKey);
        }
        Ok(Self { key_ref, bytes })
    }

    /// Constructs separate provider journal key material.
    ///
    /// # Errors
    ///
    /// Returns [`SecureStoreError::CorruptProviderJournalKey`] for all-zero
    /// key material.
    pub fn new(key_ref: ProviderJournalKeyRef, bytes: [u8; 32]) -> Result<Self, SecureStoreError> {
        #[cfg(test)]
        COPY_ARRAY_CONSTRUCTOR_CALLS.fetch_add(1, Ordering::Relaxed);
        if bytes == [0; 32] {
            return Err(SecureStoreError::CorruptProviderJournalKey);
        }
        Ok(Self {
            key_ref,
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Returns the non-secret key reference.
    #[must_use]
    pub const fn key_ref(&self) -> ProviderJournalKeyRef {
        self.key_ref
    }

    /// Borrows key bytes only for the duration of `operation`.
    pub fn with_bytes<T>(&self, operation: impl FnOnce(&[u8; 32]) -> T) -> T {
        operation(&self.bytes)
    }
}

impl fmt::Debug for ProviderJournalKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderJournalKeyMaterial")
            .field("key_ref", &self.key_ref)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Proof required before deleting retired key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderJournalKeyDeletionProof {
    backup_evidence_digest: [u8; 32],
}

impl ProviderJournalKeyDeletionProof {
    /// Test-only stand-in for a future trusted backup-catalog/GC barrier.
    ///
    /// Production code intentionally has no constructor until the durable
    /// backup catalog can mint this proof from authoritative inventory.
    #[cfg(test)]
    pub(crate) fn for_verified_catalog(
        database_reference_count: u64,
        backup_reference_count: u64,
        backup_evidence_digest: [u8; 32],
    ) -> Result<Self, SecureStoreError> {
        if database_reference_count != 0
            || backup_reference_count != 0
            || backup_evidence_digest == [0; 32]
        {
            return Err(SecureStoreError::DeletionDenied);
        }
        Ok(Self {
            backup_evidence_digest,
        })
    }

    /// Returns the non-secret backup/restore evidence digest.
    #[must_use]
    pub const fn backup_evidence_digest(self) -> [u8; 32] {
        self.backup_evidence_digest
    }
}

/// Native secure-store boundary for active and retired provider journal keys.
pub trait ProviderJournalKeyring: Send + Sync {
    /// Whether the backend can retain active and retired versions concurrently.
    fn retains_multiple_provider_journal_keys(&self) -> bool;

    /// Returns metadata-only availability without materializing key bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed secure-store error when metadata cannot be queried
    /// without weakening the backend or exact key binding.
    fn provider_journal_key_status(
        &self,
        _key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        Ok(ProviderJournalKeyStatus::Unsupported)
    }

    /// Persists one authority/generation-bound key version.
    ///
    /// # Errors
    ///
    /// Returns a typed secure-store error when the backend is unavailable or
    /// the existing item conflicts with the exact key binding.
    fn store_provider_journal_key(
        &self,
        key: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError>;

    /// Loads one exact authority/generation-bound key version.
    ///
    /// # Errors
    ///
    /// Returns a typed secure-store error when the backend, key material or
    /// exact authority/generation binding is unavailable.
    fn load_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError>;

    /// Deletes retired material only with zero-reference and backup evidence.
    ///
    /// # Errors
    ///
    /// Returns a typed secure-store error when deletion is unsupported,
    /// denied, or the exact key item cannot be removed.
    fn delete_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
        proof: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_catalog_proof_requires_zero_references_and_evidence() {
        assert_eq!(
            ProviderJournalKeyDeletionProof::for_verified_catalog(1, 0, [9; 32]),
            Err(SecureStoreError::DeletionDenied)
        );
        assert_eq!(
            ProviderJournalKeyDeletionProof::for_verified_catalog(0, 1, [9; 32]),
            Err(SecureStoreError::DeletionDenied)
        );
        assert_eq!(
            ProviderJournalKeyDeletionProof::for_verified_catalog(0, 0, [0; 32]),
            Err(SecureStoreError::DeletionDenied)
        );
        assert!(ProviderJournalKeyDeletionProof::for_verified_catalog(0, 0, [9; 32]).is_ok());
    }

    #[test]
    fn generation_never_routes_rng_bytes_through_copy_array_constructor() {
        COPY_ARRAY_CONSTRUCTOR_CALLS.store(0, Ordering::Relaxed);
        let key_ref = ProviderJournalKeyRef::new([1; 16], 1, [2; 16], 1).unwrap();

        let generated = ProviderJournalKeyMaterial::generate(key_ref).unwrap();

        assert_ne!(generated.with_bytes(|bytes| *bytes), [0; 32]);
        assert_eq!(COPY_ARRAY_CONSTRUCTOR_CALLS.load(Ordering::Relaxed), 0);
    }
}
