use runne_provider::{ScannerError, SecureStoreError};

use super::types::ScannerRecoveryPersistenceError;

/// Closed operation identifier for a provider redaction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionFailureSite {
    /// Loading prior recovery state while opening a session.
    StartRecoveryLoad,
    /// Purging stale tails while opening a session.
    StartPurge,
    /// Validating the matcher while opening a session.
    StartMatcherValidation,
    /// Loading durable recovery metadata during restart.
    RestartRecoveryLoad,
    /// Checking the recovery authority binding.
    RestartAuthorityBinding,
    /// Validating the durable scanner checkpoint.
    RestartCheckpointValidation,
    /// Loading the checkpoint tail from secure storage.
    RestartTailLoad,
    /// Purging orphaned tails during restart.
    RestartTailPurge,
    /// Validating the matcher during restart.
    RestartMatcherValidation,
    /// Checking the next scanner cursor.
    IngestCursorValidation,
    /// Loading the previous withheld tail.
    IngestTailLoad,
    /// Storing the updated withheld tail.
    IngestTailPut,
    /// Constructing the next scanner checkpoint.
    IngestCheckpointConstruction,
    /// Persisting the next checkpoint.
    IngestCheckpointPersist,
    /// Advancing the durable scanner cursor.
    IngestCheckpointAdvance,
    /// Deleting the previous withheld tail.
    IngestPreviousTailDelete,
    /// Classifying the provider chunk.
    IngestScannerClassification,
    /// Loading the final withheld tail.
    CompleteTailLoad,
    /// Storing the final withheld tail.
    CompleteTailPut,
    /// Constructing the final scanner checkpoint.
    CompleteCheckpointConstruction,
    /// Persisting the final checkpoint.
    CompleteCheckpointPersist,
    /// Advancing the durable final cursor.
    CompleteCheckpointAdvance,
    /// Purging tails after completion.
    CompleteTailPurge,
    /// Classifying the final provider chunk.
    CompleteScannerClassification,
}

impl RedactionFailureSite {
    /// Returns the exact allowlisted label for this operation.
    pub const fn stage(self) -> &'static str {
        match self {
            Self::StartRecoveryLoad => "provider_redaction_start_recovery_load",
            Self::StartPurge => "provider_redaction_start_purge",
            Self::StartMatcherValidation => "provider_redaction_start_matcher_validation",
            Self::RestartRecoveryLoad => "provider_redaction_restart_recovery_load",
            Self::RestartAuthorityBinding => "provider_redaction_restart_authority_binding",
            Self::RestartCheckpointValidation => "provider_redaction_restart_checkpoint_validation",
            Self::RestartTailLoad => "provider_redaction_restart_tail_load",
            Self::RestartTailPurge => "provider_redaction_restart_tail_purge",
            Self::RestartMatcherValidation => "provider_redaction_restart_matcher_validation",
            Self::IngestCursorValidation => "provider_redaction_ingest_cursor_validation",
            Self::IngestTailLoad => "provider_redaction_ingest_tail_load",
            Self::IngestTailPut => "provider_redaction_ingest_tail_put",
            Self::IngestCheckpointConstruction => {
                "provider_redaction_ingest_checkpoint_construction"
            }
            Self::IngestCheckpointPersist => "provider_redaction_ingest_checkpoint_persist",
            Self::IngestCheckpointAdvance => "provider_redaction_ingest_checkpoint_advance",
            Self::IngestPreviousTailDelete => "provider_redaction_ingest_previous_tail_delete",
            Self::IngestScannerClassification => "provider_redaction_ingest_scanner_classification",
            Self::CompleteTailLoad => "provider_redaction_complete_tail_load",
            Self::CompleteTailPut => "provider_redaction_complete_tail_put",
            Self::CompleteCheckpointConstruction => {
                "provider_redaction_complete_checkpoint_construction"
            }
            Self::CompleteCheckpointPersist => "provider_redaction_complete_checkpoint_persist",
            Self::CompleteCheckpointAdvance => "provider_redaction_complete_checkpoint_advance",
            Self::CompleteTailPurge => "provider_redaction_complete_tail_purge",
            Self::CompleteScannerClassification => {
                "provider_redaction_complete_scanner_classification"
            }
        }
    }
}

/// Closed, non-secret classification of a provider redaction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionFailureKind {
    /// The secure native store was unavailable.
    NativeUnavailable,
    /// The secure native item was missing.
    NativeNotFound,
    /// The secure native item was corrupt.
    NativeCorrupt,
    /// The secure native item had a different binding.
    NativeBindingMismatch,
    /// The recovery persistence layer was unavailable.
    RecoveryUnavailable,
    /// Recovery metadata conflicted with existing state.
    RecoveryConflict,
    /// Recovery metadata was corrupt.
    RecoveryCorrupt,
    /// Recovery metadata was missing.
    RecoveryMissing,
    /// The scanner authority binding did not match.
    BindingMismatch,
    /// The scanner checkpoint did not match durable metadata.
    CheckpointMismatch,
    /// The scanner rejected its binding.
    InvalidBinding,
    /// The scanner rejected its checkpoint.
    InvalidCheckpoint,
    /// The credential matcher was unavailable.
    MatcherUnavailable,
    /// The scanner was unavailable.
    ScannerUnavailable,
    /// The scanner output limit was exceeded.
    OutputLimitExceeded,
}

impl RedactionFailureKind {
    /// Returns the exact allowlisted label for this error class.
    pub const fn stage(self) -> &'static str {
        match self {
            Self::NativeUnavailable => "provider_redaction_error_native_unavailable",
            Self::NativeNotFound => "provider_redaction_error_native_not_found",
            Self::NativeCorrupt => "provider_redaction_error_native_corrupt",
            Self::NativeBindingMismatch => "provider_redaction_error_native_binding_mismatch",
            Self::RecoveryUnavailable => "provider_redaction_error_recovery_unavailable",
            Self::RecoveryConflict => "provider_redaction_error_recovery_conflict",
            Self::RecoveryCorrupt => "provider_redaction_error_recovery_corrupt",
            Self::RecoveryMissing => "provider_redaction_error_recovery_missing",
            Self::BindingMismatch => "provider_redaction_error_binding_mismatch",
            Self::CheckpointMismatch => "provider_redaction_error_checkpoint_mismatch",
            Self::InvalidBinding => "provider_redaction_error_invalid_binding",
            Self::InvalidCheckpoint => "provider_redaction_error_invalid_checkpoint",
            Self::MatcherUnavailable => "provider_redaction_error_matcher_unavailable",
            Self::ScannerUnavailable => "provider_redaction_error_scanner_unavailable",
            Self::OutputLimitExceeded => "provider_redaction_error_output_limit_exceeded",
        }
    }
}

/// Receives fixed scanner failure codes for qualification diagnostics.
pub trait ProviderRedactionObserver: Send + Sync {
    /// Reports the operation and closed error class without secret material.
    fn observe_failure(&self, site: RedactionFailureSite, kind: RedactionFailureKind);
}

/// Maps a secure-store failure to a fixed, non-secret classification.
pub(super) const fn tail_failure_kind(error: SecureStoreError) -> RedactionFailureKind {
    match error {
        SecureStoreError::Unavailable => RedactionFailureKind::NativeUnavailable,
        SecureStoreError::NotFound => RedactionFailureKind::NativeNotFound,
        SecureStoreError::Corrupt => RedactionFailureKind::NativeCorrupt,
        SecureStoreError::BindingMismatch => RedactionFailureKind::NativeBindingMismatch,
    }
}

/// Maps a persistence failure to a fixed, non-secret classification.
pub(super) const fn recovery_failure_kind(
    error: ScannerRecoveryPersistenceError,
) -> RedactionFailureKind {
    match error {
        ScannerRecoveryPersistenceError::Unavailable => RedactionFailureKind::RecoveryUnavailable,
        ScannerRecoveryPersistenceError::Conflict => RedactionFailureKind::RecoveryConflict,
        ScannerRecoveryPersistenceError::Corrupt => RedactionFailureKind::RecoveryCorrupt,
    }
}

/// Maps a scanner failure to a fixed, non-secret classification.
pub(super) const fn scanner_failure_kind(error: ScannerError) -> RedactionFailureKind {
    match error {
        ScannerError::InvalidBinding => RedactionFailureKind::InvalidBinding,
        ScannerError::InvalidCheckpoint => RedactionFailureKind::InvalidCheckpoint,
        ScannerError::MatcherUnavailable => RedactionFailureKind::MatcherUnavailable,
        ScannerError::ScannerUnavailable => RedactionFailureKind::ScannerUnavailable,
        ScannerError::OutputLimitExceeded => RedactionFailureKind::OutputLimitExceeded,
    }
}
