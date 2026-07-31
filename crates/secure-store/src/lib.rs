//! OS-backed credential and key storage boundary.
//!
//! Stores a single authenticated `db_generation` anchor in the OS secure
//! store. macOS uses Keychain; other platform backends remain fail-closed
//! until their native capability spikes are accepted.
//! The anchor must match the `SQLite` `meta.db_generation` on every open;
//! mismatch enters a named fail-closed state per `CLIENT_STORAGE_AND_RECOVERY.md`.

use std::fmt;
use thiserror::Error;

mod provider_credential;
mod provider_journal_key;

pub use provider_credential::{
    MAX_PROVIDER_CREDENTIAL_BYTES, PROVIDER_CREDENTIAL_SERVICE, ProviderCredentialAccessPolicy,
    ProviderCredentialId, ProviderCredentialMaterial, ProviderCredentialStatus,
    ProviderCredentialStore,
};
pub use provider_journal_key::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyring,
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
    #[error("secure-store anchor is corrupt")]
    CorruptAnchor,
    #[error("anchor not found")]
    NotFound,
    #[error("provider journal key is corrupt or has the wrong authority binding")]
    CorruptProviderJournalKey,
    #[error("provider journal key was not found")]
    ProviderJournalKeyNotFound,
    #[error("secure-store backend cannot retain provider journal key versions")]
    RetentionUnsupported,
    #[error("provider journal key deletion proof was denied")]
    DeletionDenied,
    #[error("provider journal key generation failed")]
    ProviderJournalKeyGenerationFailed,
    #[error("native secure-store backend is unsupported")]
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
pub trait SecureStore: Send + Sync {
    /// Persist the anchor.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform secure store cannot persist the anchor.
    fn store_anchor(&self, generation: u64) -> Result<(), SecureStoreError>;

    /// Read the current anchor, if any.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform secure store is unavailable or the
    /// stored anchor is corrupt.
    fn read_anchor(&self) -> Result<Option<u64>, SecureStoreError>;

    /// Delete the anchor (used during profile reset).
    ///
    /// # Errors
    ///
    /// Returns an error when the platform secure store cannot delete the anchor.
    fn delete_anchor(&self) -> Result<(), SecureStoreError>;
}

// ---------------------------------------------------------------------------
// Platform implementation — macOS Keychain
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::MacOsKeychainStore;

#[cfg(target_os = "macos")]
pub use macos::MacOsProviderCredentialStore as NativeProviderCredentialStore;

// ---------------------------------------------------------------------------
// Stub implementations for platforms not yet wired
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
mod stub;

#[cfg(not(target_os = "macos"))]
pub use stub::StubStore;

#[cfg(not(target_os = "macos"))]
pub use stub::StubStore as NativeProviderCredentialStore;
