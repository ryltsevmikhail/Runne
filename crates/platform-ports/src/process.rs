//! Domain-neutral process platform contracts with no native implementation.

mod port;
mod request;
mod types;

pub use port::{
    NoProcessStartedEvidenceV1, ProcessLaunchEvidenceV1, ProcessLaunchOutcomeV1,
    ProcessOwnerVerificationV1, ProcessPlatformFailure, ProcessPlatformPort,
    ProcessStubDisposition, ProcessTerminalDispositionV1, ProcessTerminalEvidenceV1,
    ProcessTreeCleanupV1,
};
pub use request::{MonotonicDeadline, MonotonicDeadlineErrorV1, ProcessPlatformRequestV1};
pub use types::{
    HeldFileIdentityV1, HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessFileKindV1,
    ProcessGenerationIdV1, ProcessLifecycleBindingV1, ProcessOwnerIdV1, ProcessSessionIdV1,
    ProcessSymlinkProofV1, ProcessTypeValidationError, VerifiedCwdV1, VerifiedExecutableV1,
};

#[cfg(test)]
mod tests;
