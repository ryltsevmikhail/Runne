//! OS-backed credential and key storage boundary.
//!
//! Stores a single authenticated `db_generation` anchor in the OS secure
//! store. macOS uses Keychain; Linux uses Secret Service/keyutils and Windows
//! uses Credential Manager through the native keyring adapter.
//! The anchor must match the `SQLite` `meta.db_generation` on every open;
//! mismatch enters a named fail-closed state per `CLIENT_STORAGE_AND_RECOVERY.md`.

use std::fmt;
use thiserror::Error;

mod payload_crypto;
#[cfg(feature = "project-owner-key-store")]
mod project_owner_key;
#[cfg(feature = "project-owner-key-store")]
mod project_owner_key_store;
#[cfg(all(test, feature = "project-owner-key-store", not(target_os = "macos")))]
mod project_owner_key_tests;
#[cfg(all(test, feature = "project-owner-key-store", not(target_os = "macos")))]
mod project_owner_key_transaction_tests;
#[cfg(feature = "project-owner-key-store")]
mod project_owner_keychain_policy;
#[cfg_attr(any(target_os = "linux", target_os = "windows"), allow(dead_code))]
mod provider_credential;
mod provider_journal_key;
mod provider_recovery;
pub(crate) mod security_anchor;
#[cfg(feature = "test-support")]
pub mod test_support;

#[cfg(all(feature = "project-owner-key-store", target_os = "macos"))]
pub use project_owner_key::{CodeSignIdentity, MacosProjectOwnerKeyStore};
#[cfg(feature = "project-owner-key-store")]
pub use project_owner_key::{
    MAX_PROJECT_OWNER_TRANSCRIPT_BYTES, PendingProjectOwnerKey, ProjectOwnerAnchorFloor,
    ProjectOwnerKeyMaterial, ProjectOwnerKeyRef, StoreStatus,
};
#[cfg(feature = "project-owner-key-store")]
pub use project_owner_key_store::{ProjectOwnerKeyStore, validate_transcript};
#[cfg(feature = "project-owner-key-store")]
pub use project_owner_keychain_policy::{
    PROJECT_OWNER_KEYCHAIN_ACCESS_GROUP, PROJECT_OWNER_KEYCHAIN_SERVICE,
    ProjectOwnerKeychainAccount, ProjectOwnerKeychainQuery, map_project_owner_keychain_status,
};
#[cfg(feature = "provider-credential-broker-writer")]
pub use provider_credential::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, BrokeredProviderCredentialLegacySource,
    BrokeredProviderCredentialWriter, BrokeredWriterIdentityMigrationInput,
    BrokeredWriterIdentityVerificationInput, NativeProviderCredentialEffectRoute,
    NativeProviderCredentialWriters, WriterIdentityMigrationObservation,
};
pub use provider_credential::{
    CredentialReadbackObservation, ExactAbsenceReadback, ExactVersionReadback,
    MAX_NATIVE_OAUTH_CREDENTIAL_BYTES, MAX_PROVIDER_CREDENTIAL_BYTES, NativeLegacySourceReadback,
    NativeProviderCredentialReaderParts, NativeProviderCredentialReaders,
    NativeProviderCredentialVerificationMaterializer, NativeProviderCredentialVersionStore,
    PROVIDER_CREDENTIAL_SERVICE, ProviderCredentialAccessPolicy,
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead, ProviderCredentialId,
    ProviderCredentialMaterial, ProviderCredentialMaterialKind, ProviderCredentialReadback,
    ProviderCredentialRecoveryRead, ProviderCredentialSource, ProviderCredentialSourceRevision,
    ProviderCredentialStatus, ProviderCredentialStore, ProviderCredentialVerificationMaterializer,
    ProviderCredentialVerificationReadback, VerificationMaterializerAdapter,
    VerificationNativeMaterializer, native_verification_materializer,
};
pub use provider_journal_key::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring,
};
pub use provider_recovery::NativeWithheldTailStore;
pub use security_anchor::{
    MAX_SEALED_TRANSACTION_TAG_BYTES, SealedTransactionTag, SecurityAnchorV1, SecurityProfileLock,
    StoredSecurityAnchor,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecureStoreError {
    #[error("secure store is unavailable on this platform")]
    Unavailable,
    #[error("secure store operation failed: {0}")]
    OperationFailed(String),
    #[error("runne-secure-store anchor is corrupt")]
    CorruptAnchor,
    #[error("security profile lock does not match the requested anchor")]
    LockMismatch,
    #[error("security anchor compare-and-advance conflict")]
    AnchorConflict,
    #[error("security anchor transition is invalid")]
    InvalidTransition,
    #[error("security transaction seal is invalid")]
    InvalidSeal,
    #[error("anchor not found")]
    NotFound,
    #[error("provider journal key is corrupt or has the wrong authority binding")]
    CorruptProviderJournalKey,
    #[error("provider journal key was not found")]
    ProviderJournalKeyNotFound,
    #[error("runne-secure-store backend cannot retain provider journal key versions")]
    RetentionUnsupported,
    #[error("provider journal key deletion proof was denied")]
    DeletionDenied,
    #[error("provider journal key generation failed")]
    ProviderJournalKeyGenerationFailed,
    #[error("native runne-secure-store backend is unsupported")]
    UnsupportedSecureStoreBackend,
    #[error("provider credential is invalid")]
    InvalidProviderCredential,
    #[error("provider credential was not found")]
    ProviderCredentialNotFound,
    #[error("provider credential access was denied")]
    CredentialAccessDenied,
    #[error("provider credential executable identity mismatch")]
    CredentialIdentityMismatch,
    #[error("provider credential ACL migration is required")]
    CredentialAclMigrationRequired,
    #[error("provider credential item is corrupt")]
    CorruptProviderCredential,
    #[error("provider credential operation failed")]
    ProviderCredentialOperationFailed,
    #[error("provider credential enrollment is incomplete")]
    CredentialEnrollmentIncomplete,
    #[error("provider credential ACL migration is incomplete")]
    CredentialMigrationIncomplete,
    #[error("provider credential source revision is unavailable")]
    ProviderCredentialSourceRevisionUnavailable,
}

// ---------------------------------------------------------------------------
// Anchor status — the documented recovery state machine
// ---------------------------------------------------------------------------

/// Classification of the database/anchor relationship on open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorStatus {
    /// Neither DB nor anchor exists — first run.
    FirstRun,
    /// DB generation == anchor — normal.
    Normal,
    /// DB generation < anchor — rollback/replacement; block connected mode.
    DbLowerThanAnchor { db_gen: u64, anchor: u64 },
    /// DB generation == anchor + 1 with valid commit marker — crash after
    /// commit; advance anchor after integrity check.
    DbOneAhead { db_gen: u64, anchor: u64 },
    /// DB generation > anchor + 1 or invalid marker — ambiguous tamper.
    DbTooFarAhead { db_gen: u64, anchor: u64 },
    /// Anchor missing but DB exists — anchor loss; block mutations.
    AnchorMissing { db_gen: u64 },
    /// DB missing but anchor exists — deletion; block.
    DbMissing { anchor: u64 },
}

impl fmt::Display for AnchorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirstRun => write!(f, "first-run"),
            Self::Normal => write!(f, "normal"),
            Self::DbLowerThanAnchor { db_gen, anchor } => {
                write!(f, "db({db_gen}) < anchor({anchor}) — rollback/replacement")
            }
            Self::DbOneAhead { db_gen, anchor } => {
                write!(
                    f,
                    "db({db_gen}) == anchor({anchor}) + 1 — crash after commit"
                )
            }
            Self::DbTooFarAhead { db_gen, anchor } => {
                write!(f, "db({db_gen}) > anchor({anchor}) + 1 — ambiguous")
            }
            Self::AnchorMissing { db_gen } => {
                write!(f, "db({db_gen}) with no anchor — anchor loss")
            }
            Self::DbMissing { anchor } => {
                write!(f, "anchor({anchor}) with no DB — deletion")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Platform-specific secure store operations for the `db_generation` anchor.
///
/// The service name and account are fixed per profile; the implementation
/// chooses the concrete OS facility.
#[allow(clippy::missing_errors_doc)]
pub trait SecureStore: Send + Sync {
    /// Acquires the non-forgeable process/profile guard used for security state.
    fn acquire_security_profile_lock(
        &self,
        _profile_identity_digest: [u8; 32],
    ) -> Result<SecurityProfileLock<'_>, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    /// Reads the exact stored anchor representation while holding its profile lock.
    fn read_security_anchor(
        &self,
        _lock: &SecurityProfileLock<'_>,
    ) -> Result<StoredSecurityAnchor, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    /// Advances the immutable V1 anchor chain only from an exact expected record.
    fn compare_and_advance_anchor(
        &self,
        _lock: &SecurityProfileLock<'_>,
        _expected: &SecurityAnchorV1,
        _next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    /// Creates only the generation-one root from a verified missing slot.
    fn initialize_security_anchor(
        &self,
        _lock: &SecurityProfileLock<'_>,
        _next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    /// Replaces a verified legacy generation with exactly one V1 migration root.
    fn compare_and_migrate_legacy_anchor(
        &self,
        _lock: &SecurityProfileLock<'_>,
        _expected_generation: u64,
        _next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    /// Seals a prospective transaction with the platform-owned key material.
    fn seal_security_transaction(
        &self,
        _lock: &SecurityProfileLock<'_>,
        _database_identity: [u8; 32],
        _generation: u64,
        _transaction_digest: [u8; 32],
        _previous_anchor_digest: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    /// Verifies an already persisted seal; recovery never creates a replacement.
    fn verify_security_transaction(
        &self,
        _lock: &SecurityProfileLock<'_>,
        _anchor: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }
}

// ---------------------------------------------------------------------------
// Platform implementation — macOS Keychain
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::MacOsKeychainStore;

#[cfg(target_os = "macos")]
pub use macos::MacOsPlainProviderCredentialStore;
#[cfg(target_os = "macos")]
pub use macos::MacOsProviderCredentialStore;
#[cfg(target_os = "macos")]
pub use macos::MacOsPlainProviderCredentialStore as NativeProviderCredentialStore;

#[cfg(all(target_os = "macos", feature = "test-support"))]
pub use macos::ScenarioSourceSlotSeed;

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod keyring;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use keyring::NativeKeyringStore;
#[cfg(all(target_os = "linux", feature = "test-support"))]
pub use keyring::linux_provider_source::{
    CountingFakeSource, DirectoryFakeSource, install_test_source,
};

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use keyring::NativeKeyringStore as NativeProviderCredentialStore;

// ---------------------------------------------------------------------------
// Stub implementations for unsupported targets
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
mod platform_stub;

#[cfg(not(target_os = "macos"))]
pub use platform_stub::StubStore;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub use platform_stub::StubStore as NativeProviderCredentialStore;
