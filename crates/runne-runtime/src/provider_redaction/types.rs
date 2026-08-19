use runne_provider::{
    DispatchAttemptId, ScannerCheckpoint, ScannerTerminalDisposition, TailBinding,
};
use thiserror::Error;

/// Non-secret durable scanner recovery projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerRecoveryRecord {
    binding: TailBinding,
    checkpoint: Option<ScannerCheckpoint>,
    durable_cursor: u64,
    durable_safe_prefix_high_water: u64,
    durable_checkpoint_digest: Option<[u8; 32]>,
    completion_checkpoint_digest: Option<[u8; 32]>,
    disposition: Option<ScannerTerminalDisposition>,
}

impl ScannerRecoveryRecord {
    /// Constructs a persistence read model.
    pub const fn new(
        binding: TailBinding,
        checkpoint: Option<ScannerCheckpoint>,
        durable_cursor: u64,
        durable_safe_prefix_high_water: u64,
        durable_checkpoint_digest: Option<[u8; 32]>,
        completion_checkpoint_digest: Option<[u8; 32]>,
        disposition: Option<ScannerTerminalDisposition>,
    ) -> Self {
        Self {
            binding,
            checkpoint,
            durable_cursor,
            durable_safe_prefix_high_water,
            durable_checkpoint_digest,
            completion_checkpoint_digest,
            disposition,
        }
    }
    /// Returns the durable attempt, fence, policy, matcher and cursor binding.
    pub const fn binding(self) -> TailBinding {
        self.binding
    }
    /// Returns the exact canonical checkpoint, when committed.
    pub const fn checkpoint(self) -> Option<ScannerCheckpoint> {
        self.checkpoint
    }
    /// Returns the cursor bound to the checkpoint digest.
    pub const fn durable_cursor(self) -> u64 {
        self.durable_cursor
    }
    /// Returns the safe-prefix high-water bound to the checkpoint digest.
    pub const fn durable_safe_prefix_high_water(self) -> u64 {
        self.durable_safe_prefix_high_water
    }
    /// Returns the exact digest authorizing the durable cursor advance.
    pub const fn durable_checkpoint_digest(self) -> Option<[u8; 32]> {
        self.durable_checkpoint_digest
    }
    /// Returns the final empty-tail checkpoint marker, when durably proven.
    pub const fn completion_checkpoint_digest(self) -> Option<[u8; 32]> {
        self.completion_checkpoint_digest
    }
    /// Returns the committed terminal disposition, when terminal.
    pub const fn disposition(self) -> Option<ScannerTerminalDisposition> {
        self.disposition
    }
}

/// Closed persistence error without secret-bearing diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ScannerRecoveryPersistenceError {
    /// Durable scanner state is unavailable.
    #[error("scanner recovery persistence is unavailable")]
    Unavailable,
    /// Durable scanner state conflicts with the exact authority binding.
    #[error("scanner recovery persistence conflicts")]
    Conflict,
    /// Durable checkpoint bytes or ordering are corrupt.
    #[error("scanner recovery persistence is corrupt")]
    Corrupt,
}

/// Closed runtime scanner failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderRedactionError {
    /// Durable recovery metadata is unavailable.
    #[error("provider redaction recovery persistence is unavailable")]
    PersistenceUnavailable,
    /// Scanner input exceeded a bounded limit.
    #[error("provider redaction output limit was exceeded")]
    OutputLimitExceeded,
}

pub(super) const fn map_persistence_error(
    _: ScannerRecoveryPersistenceError,
) -> ProviderRedactionError {
    ProviderRedactionError::PersistenceUnavailable
}

/// Managed persistence port enforcing checkpoint-before-cursor ordering.
pub trait ScannerRecoveryPersistence: Send + Sync {
    /// Persists one opaque canonical checkpoint before cursor advance.
    fn persist_checkpoint(
        &self,
        checkpoint: ScannerCheckpoint,
    ) -> Result<(), ScannerRecoveryPersistenceError>;
    /// Advances cursor/high-water only when bound to the exact checkpoint digest.
    fn advance_checkpoint(
        &self,
        checkpoint: ScannerCheckpoint,
    ) -> Result<(), ScannerRecoveryPersistenceError>;
    /// Advances the exact final empty-tail checkpoint and marks completion proof.
    fn advance_final_checkpoint(
        &self,
        checkpoint: ScannerCheckpoint,
    ) -> Result<(), ScannerRecoveryPersistenceError>;
    /// Commits a monotonic terminal disposition without creating publication.
    fn commit_terminal(
        &self,
        binding: TailBinding,
        disposition: ScannerTerminalDisposition,
    ) -> Result<ScannerTerminalDisposition, ScannerRecoveryPersistenceError>;
    /// Terminalizes only an atomically revalidated corrupt checkpoint row.
    fn terminalize_corrupt_checkpoint(
        &self,
        expected_binding: TailBinding,
    ) -> Result<ScannerTerminalDisposition, ScannerRecoveryPersistenceError>;
    /// Loads one non-secret recovery projection.
    fn load(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Option<ScannerRecoveryRecord>, ScannerRecoveryPersistenceError>;
}
