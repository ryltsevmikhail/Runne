use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::DispatchAttemptId;

const TAIL_BINDING_V1: &[u8] = b"RUNNE_WITHHELD_TAIL_BINDING_V1\0";

/// Opaque native identity for attempt-scoped withheld bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NativeSecretRef {
    id: [u8; 16],
    version: u32,
    binding_digest: [u8; 32],
}

impl NativeSecretRef {
    /// Constructs a non-zero opaque reference.
    pub fn new(
        id: [u8; 16],
        version: u32,
        binding_digest: [u8; 32],
    ) -> Result<Self, SecureStoreError> {
        if id == [0; 16] || version == 0 || binding_digest == [0; 32] {
            return Err(SecureStoreError::Corrupt);
        }
        Ok(Self {
            id,
            version,
            binding_digest,
        })
    }

    /// Returns the opaque native item identity.
    pub const fn id(self) -> [u8; 16] {
        self.id
    }

    /// Returns the positive native item version.
    pub const fn version(self) -> u32 {
        self.version
    }

    /// Returns the non-secret authority-binding digest.
    pub const fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }
}

/// Exact non-secret authority and scanner binding for one withheld tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailBinding {
    attempt_id: DispatchAttemptId,
    fencing_token: u64,
    policy_epoch: u64,
    matcher_epoch: u64,
    algorithm_version: u32,
    cursor: u64,
}

impl TailBinding {
    /// Constructs a complete attempt/fence/policy/matcher/cursor binding.
    pub fn new(
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        policy_epoch: u64,
        matcher_epoch: u64,
        algorithm_version: u32,
        cursor: u64,
    ) -> Result<Self, ScannerError> {
        if fencing_token == 0 || policy_epoch == 0 || matcher_epoch == 0 || algorithm_version == 0 {
            return Err(ScannerError::InvalidBinding);
        }
        Ok(Self {
            attempt_id,
            fencing_token,
            policy_epoch,
            matcher_epoch,
            algorithm_version,
            cursor,
        })
    }

    /// Returns the provider attempt identity.
    pub const fn attempt_id(self) -> DispatchAttemptId {
        self.attempt_id
    }
    /// Returns the active fencing token.
    pub const fn fencing_token(self) -> u64 {
        self.fencing_token
    }
    /// Returns the pinned prohibited-content policy epoch.
    pub const fn policy_epoch(self) -> u64 {
        self.policy_epoch
    }
    /// Returns the pinned matcher epoch.
    pub const fn matcher_epoch(self) -> u64 {
        self.matcher_epoch
    }
    /// Returns the scanner algorithm version.
    pub const fn algorithm_version(self) -> u32 {
        self.algorithm_version
    }
    /// Returns the provider byte cursor represented by this binding.
    pub const fn cursor(self) -> u64 {
        self.cursor
    }

    /// Returns the canonical non-secret binding digest.
    pub fn digest(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(TAIL_BINDING_V1);
        hasher.update(self.attempt_id.as_bytes());
        hasher.update(self.fencing_token.to_be_bytes());
        hasher.update(self.policy_epoch.to_be_bytes());
        hasher.update(self.matcher_epoch.to_be_bytes());
        hasher.update(self.algorithm_version.to_be_bytes());
        hasher.update(self.cursor.to_be_bytes());
        hasher.finalize().into()
    }

    pub(crate) fn at_cursor(self, cursor: u64) -> Self {
        Self { cursor, ..self }
    }
}

/// Fail-closed scanner reason, ordered from strongest to weakest failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerUncertainReason {
    /// Credential material was detected and suppressed.
    SecretDetected,
    /// The exact credential matcher epoch is unavailable.
    CredentialMatcherUnavailable,
    /// The redaction scanner could not classify provider bytes.
    RedactionScannerUnavailable,
    /// The opaque checkpoint or native tail cannot be reconstructed exactly.
    CheckpointSecretStateUnavailable,
}

/// Monotonic scanner terminal lattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerTerminalDisposition {
    /// Publication-blocking uncertain scanner state.
    Uncertain(ScannerUncertainReason),
    /// The bounded output limit was exceeded.
    OutputLimitExceeded,
    /// All provider bytes were scanned and may be published.
    Completed,
}

impl ScannerTerminalDisposition {
    /// Returns the stronger disposition, preventing terminal downgrade.
    pub const fn dominant(self, candidate: Self) -> Self {
        if terminal_rank(self) <= terminal_rank(candidate) {
            self
        } else {
            candidate
        }
    }
}

const fn terminal_rank(value: ScannerTerminalDisposition) -> u8 {
    match value {
        ScannerTerminalDisposition::Uncertain(ScannerUncertainReason::SecretDetected) => 0,
        ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CredentialMatcherUnavailable,
        ) => 1,
        ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::RedactionScannerUnavailable,
        ) => 2,
        ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CheckpointSecretStateUnavailable,
        ) => 3,
        ScannerTerminalDisposition::OutputLimitExceeded => 4,
        ScannerTerminalDisposition::Completed => 5,
    }
}

/// Native withheld-tail backend failure with no secret-bearing diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SecureStoreError {
    /// Native secure storage is unavailable.
    #[error("native withheld-tail store is unavailable")]
    Unavailable,
    /// The opaque item does not exist.
    #[error("native withheld-tail item was not found")]
    NotFound,
    /// The item or opaque reference is corrupt.
    #[error("native withheld-tail item is corrupt")]
    Corrupt,
    /// The item has a different authority binding.
    #[error("native withheld-tail authority binding mismatched")]
    BindingMismatch,
}

/// Provider-neutral scanner failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ScannerError {
    /// Exact matcher state is unavailable.
    #[error("credential matcher is unavailable")]
    MatcherUnavailable,
    /// Scanner execution failed closed.
    #[error("redaction scanner is unavailable")]
    ScannerUnavailable,
    /// Scanner authority binding is invalid.
    #[error("scanner binding is invalid")]
    InvalidBinding,
    /// Checkpoint metadata or digest is invalid.
    #[error("scanner checkpoint is invalid")]
    InvalidCheckpoint,
    /// Cursor or output length overflowed its bound.
    #[error("scanner output limit was exceeded")]
    OutputLimitExceeded,
}

/// Native storage boundary for zeroizing withheld provider bytes.
pub trait WithheldTailStore: Send + Sync {
    /// Persists bytes under the exact authority binding and returns only an opaque reference.
    fn put_tail(
        &self,
        binding: TailBinding,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<NativeSecretRef, SecureStoreError>;
    /// Loads zeroizing bytes only for the exact opaque reference and authority binding.
    fn load_tail(
        &self,
        reference: &NativeSecretRef,
        binding: TailBinding,
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError>;
    /// Deletes one exact reference. Missing items are an idempotent success.
    fn delete_tail(&self, reference: &NativeSecretRef) -> Result<(), SecureStoreError>;
    /// Deletes attempt-scoped native refs other than the exact durable reference.
    fn purge_orphaned_tails(
        &self,
        binding: TailBinding,
        retained: Option<NativeSecretRef>,
    ) -> Result<(), SecureStoreError>;
}
