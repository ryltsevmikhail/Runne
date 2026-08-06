//! Fail-closed process platform port and replay-safe outcome contracts.

use super::{MonotonicDeadline, ProcessLifecycleBindingV1, ProcessPlatformRequestV1};

/// Closed result of exact owner verification at a platform process boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOwnerVerificationV1 {
    /// The exact owner binding was verified.
    Verified,
    /// The owner binding differed.
    Mismatch,
    /// The platform could not verify the owner binding.
    Unavailable,
    /// No process was started, so owner verification does not apply.
    NotApplicable,
}

/// Closed result of exact process-tree cleanup at a platform process boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTreeCleanupV1 {
    /// The exact held tree was cleaned up and verified terminal.
    Verified,
    /// Cleanup was attempted but could not be verified.
    Unverified,
    /// The platform could not establish cleanup status.
    Unavailable,
    /// No process was started, so tree cleanup does not apply.
    NotApplicable,
}

/// Domain-neutral process boundary with no implicit launch fallback.
pub trait ProcessPlatformPort: Send + Sync {
    /// Adapter-owned prepared value that cannot be forged by a generic caller.
    type Prepared: Send;

    /// Revalidates held identities and returns a launchable opaque token.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when validation cannot establish exact bindings.
    fn validate_and_prepare(
        &self,
        request: &ProcessPlatformRequestV1,
        deadline: MonotonicDeadline,
    ) -> Result<Self::Prepared, ProcessPlatformFailure>;

    /// Launches an already prepared process with exact lifecycle control.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when launch cannot be proven.
    fn launch(
        &self,
        prepared: Self::Prepared,
        binding: &ProcessLifecycleBindingV1,
        deadline: MonotonicDeadline,
    ) -> Result<ProcessLaunchOutcomeV1, ProcessPlatformFailure>;

    /// Terminates only the exact held process tree before a monotonic deadline.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when termination cannot be proven.
    fn terminate(
        &self,
        binding: &ProcessLifecycleBindingV1,
        deadline: MonotonicDeadline,
    ) -> Result<ProcessTerminalEvidenceV1, ProcessPlatformFailure>;
}

/// Closed evidence for a launch that definitely did not start a process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoProcessStartedEvidenceV1 {
    binding: ProcessLifecycleBindingV1,
    owner_verification: ProcessOwnerVerificationV1,
    tree_cleanup: ProcessTreeCleanupV1,
    evidence_digest: [u8; 32],
}

impl NoProcessStartedEvidenceV1 {
    /// Establishes structural validity only for no-start evidence.
    ///
    /// Provenance requires a direct configured `ProcessPlatformPort` call; the digest is
    /// neither authority nor a signature.
    ///
    /// # Errors
    ///
    /// Returns an error for an all-zero evidence digest.
    pub fn new(
        binding: &ProcessLifecycleBindingV1,
        evidence_digest: [u8; 32],
    ) -> Result<Self, ProcessPlatformFailure> {
        if evidence_digest == [0; 32] {
            return Err(ProcessPlatformFailure::TerminalEvidenceInvalid);
        }
        Ok(Self {
            binding: binding.clone(),
            owner_verification: ProcessOwnerVerificationV1::NotApplicable,
            tree_cleanup: ProcessTreeCleanupV1::NotApplicable,
            evidence_digest,
        })
    }

    /// Returns the exact lifecycle binding at the launch boundary.
    #[must_use]
    pub const fn binding(&self) -> &ProcessLifecycleBindingV1 {
        &self.binding
    }

    /// Returns the fixed no-process owner-verification disposition.
    #[must_use]
    pub const fn owner_verification(&self) -> ProcessOwnerVerificationV1 {
        self.owner_verification
    }

    /// Returns the fixed no-process tree-cleanup disposition.
    #[must_use]
    pub const fn tree_cleanup(&self) -> ProcessTreeCleanupV1 {
        self.tree_cleanup
    }
}

/// Replay-safe launch evidence bound to an opaque held tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessLaunchEvidenceV1 {
    binding: ProcessLifecycleBindingV1,
    evidence_digest: [u8; 32],
}

impl ProcessLaunchEvidenceV1 {
    /// Establishes structural validity only for launch evidence without a process identifier.
    ///
    /// Provenance requires a direct configured `ProcessPlatformPort` call; the digest is
    /// neither authority nor a signature.
    ///
    /// # Errors
    ///
    /// Returns an error for an all-zero evidence digest.
    pub fn new(
        binding: &ProcessLifecycleBindingV1,
        evidence_digest: [u8; 32],
    ) -> Result<Self, ProcessPlatformFailure> {
        if evidence_digest == [0; 32] {
            return Err(ProcessPlatformFailure::LaunchEvidenceMissing);
        }
        Ok(Self {
            binding: binding.clone(),
            evidence_digest,
        })
    }

    /// Returns the exact lifecycle binding at the launch boundary.
    #[must_use]
    pub const fn binding(&self) -> &ProcessLifecycleBindingV1 {
        &self.binding
    }
}

/// Closed launch result supplied by a platform adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessLaunchOutcomeV1 {
    /// A process started and has exact launch evidence.
    Launched(ProcessLaunchEvidenceV1),
    /// The adapter proves that no process started.
    NoProcessStarted(NoProcessStartedEvidenceV1),
}

/// Closed terminal disposition without raw exit or signal data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTerminalDispositionV1 {
    /// The process tree completed normally.
    Completed,
    /// The process tree was terminated and verified.
    Terminated,
}

/// Replay-safe terminal evidence for the exact held process tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessTerminalEvidenceV1 {
    binding: ProcessLifecycleBindingV1,
    disposition: ProcessTerminalDispositionV1,
    owner_verification: ProcessOwnerVerificationV1,
    tree_cleanup: ProcessTreeCleanupV1,
    evidence_digest: [u8; 32],
}

impl ProcessTerminalEvidenceV1 {
    /// Establishes structural validity only for terminal evidence without raw process output.
    ///
    /// Provenance requires a direct configured `ProcessPlatformPort` call; the digest is
    /// neither authority nor a signature.
    ///
    /// # Errors
    ///
    /// Returns an error for an all-zero evidence digest.
    pub fn new(
        binding: &ProcessLifecycleBindingV1,
        disposition: ProcessTerminalDispositionV1,
        owner_verification: ProcessOwnerVerificationV1,
        tree_cleanup: ProcessTreeCleanupV1,
        evidence_digest: [u8; 32],
    ) -> Result<Self, ProcessPlatformFailure> {
        if evidence_digest == [0; 32] {
            return Err(ProcessPlatformFailure::TerminalEvidenceInvalid);
        }
        Ok(Self {
            binding: binding.clone(),
            disposition,
            owner_verification,
            tree_cleanup,
            evidence_digest,
        })
    }

    /// Returns the exact lifecycle binding at the terminal boundary.
    #[must_use]
    pub const fn binding(&self) -> &ProcessLifecycleBindingV1 {
        &self.binding
    }

    /// Returns the closed terminal disposition.
    #[must_use]
    pub const fn disposition(&self) -> ProcessTerminalDispositionV1 {
        self.disposition
    }

    /// Returns the platform-owned exact owner-verification disposition.
    #[must_use]
    pub const fn owner_verification(&self) -> ProcessOwnerVerificationV1 {
        self.owner_verification
    }

    /// Returns the platform-owned exact tree-cleanup disposition.
    #[must_use]
    pub const fn tree_cleanup(&self) -> ProcessTreeCleanupV1 {
        self.tree_cleanup
    }

    /// Returns the replay-safe terminal evidence digest.
    #[must_use]
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }
}

/// Closed fail-closed disposition for a platform stub.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessStubDisposition {
    /// The target does not support this port.
    Unsupported,
    /// A required platform facility is unavailable.
    Unavailable,
    /// Native execution is not qualified.
    NotQualified,
}

/// Closed process platform failure codes with no raw platform error payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessPlatformFailure {
    /// The request contract is malformed.
    IntentMalformed,
    /// The exact request binding differs.
    IntentDigestMismatch,
    /// Capability validation failed.
    CapabilityInvalid,
    /// Approval validation failed.
    ApprovalInvalid,
    /// Outer admission is absent or invalid.
    AdmissionMissing,
    /// Reserved outer-boundary result; Task 6 neither emits nor proves it.
    PermitAlreadyConsumed,
    /// A claim projection conflicts with an exact binding.
    ClaimProjectionConflict,
    /// Executable held identity validation failed.
    ExecutableVerificationFailed,
    /// Working-directory held identity validation failed.
    CwdVerificationFailed,
    /// Bounded input validation failed.
    InputBoundsExceeded,
    /// Owner, attempt, session, or generation differs.
    GenerationMismatch,
    /// The platform stub refused before any native boundary.
    Disposition(ProcessStubDisposition),
    /// The adapter proves that no process started.
    NoProcessStarted,
    /// Launch cannot be proven.
    LaunchEvidenceMissing,
    /// Lifecycle binding does not match the held tree.
    LifecycleControlMismatch,
    /// Tree termination cannot be verified.
    TerminationUnverified,
    /// Terminal evidence is malformed or mismatched.
    TerminalEvidenceInvalid,
    /// Evidence loss leaves the process state uncertain.
    ProcessUncertain,
}
