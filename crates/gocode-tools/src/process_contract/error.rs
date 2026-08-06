use thiserror::Error;

/// Closed failures for process claim projection and lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProcessContractErrorV1 {
    /// The outer admission is absent, invalid, or cannot be projected.
    #[error("process admission is missing")]
    AdmissionMissing,
    /// The exact identity binding is malformed or does not match.
    #[error("process identity binding does not match")]
    GenerationMismatch,
    /// An existing permit projection has a different exact claim binding.
    #[error("process claim projection conflicts with the existing record")]
    ClaimProjectionConflict,
    /// The requested state change is outside the closed lifecycle graph.
    #[error("process lifecycle transition is invalid")]
    InvalidLifecycleTransition,
    /// A terminal receipt could not be committed with its completed state.
    #[error("process terminal receipt commit failed")]
    TerminalCommitFailed,
    /// A different terminal receipt conflicts with the replay-safe receipt.
    #[error("process terminal receipt conflicts with the existing receipt")]
    TerminalReceiptConflict,
    /// A different proof, output metadata, revision, or sequence conflicts with settlement.
    #[error("process terminal settlement conflicts with the existing settlement")]
    SettlementConflict,
    /// A required stdin or output bound was exceeded.
    #[error("process input or output bounds are exceeded")]
    InputBoundsExceeded,
    /// Safe terminal evidence metadata is incomplete or contains a sentinel value.
    #[error("process terminal evidence is malformed")]
    EvidenceMalformed,
    /// The sealed witness could not form a platform request.
    #[error("sealed process witness cannot form a platform request")]
    PlatformRequestRejected,
    /// A CAS-derived revision or terminal sequence cannot advance without wrapping.
    #[error("process record metadata overflowed")]
    MetadataOverflow,
}
