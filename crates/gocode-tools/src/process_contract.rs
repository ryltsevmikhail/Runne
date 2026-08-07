#![cfg_attr(not(test), allow(dead_code, unused_imports))]

//! Marker-safe process claim projection and closed lifecycle contracts.
//!
//! Task 7B exposes only a sealed host with a closed platform target and
//! metadata-only in-memory journal. Task 6 invariants remain preserved: the
//! outer permit is the sole effect authority, no implicit retry exists, and
//! raw output remains private to the exact authorized route.

mod claim;
mod control;
mod error;
mod evidence;
#[cfg(test)]
mod fixture;
#[cfg(test)]
mod fixture_ports;
mod host;
mod journal;
mod journal_memory;
mod lifecycle;
mod orchestrator;
mod orchestrator_input;
#[cfg(test)]
mod orchestrator_marker_tests;
#[cfg(test)]
mod orchestrator_output_tests;
mod orchestrator_settlement;
mod orchestrator_supervision;
#[cfg(test)]
mod orchestrator_supervision_completion_tests;
#[cfg(test)]
mod orchestrator_supervision_tests;
mod orchestrator_termination;
mod output;
#[cfg(test)]
mod recovery_tests;
mod settlement;

#[cfg(test)]
mod claim_unit_tests;
#[cfg(test)]
mod f1_replay_tests;
#[cfg(test)]
mod f1_tests;
#[cfg(test)]
mod fixture_tests;
#[cfg(test)]
mod lifecycle_unit_tests;
#[cfg(test)]
mod orchestrator_failure_tests;
#[cfg(test)]
mod orchestrator_lifecycle_tests;
#[cfg(test)]
mod orchestrator_termination_tests;
#[cfg(test)]
mod orchestrator_test_support;
#[cfg(test)]
mod orchestrator_tests;
#[cfg(test)]
mod settlement_unit_tests;

pub(crate) use claim::{ProcessClaimBindingV1, ProcessClaimInputV1};
pub(crate) use claim::{ProcessClaimJournalPort, ProcessClaimKeyV1, ProcessClaimRecordV1};
pub(crate) use control::ProcessControlPortV1;
pub use error::ProcessContractErrorV1;
pub use evidence::{ProcessAuditRecordV1, ProcessAuditStageV1};
#[cfg(test)]
use fixture::{
    VirtualFixtureErrorV1, VirtualGraceScriptV1, VirtualLaunchScriptV1, VirtualProcessCallV1,
    VirtualProcessTreeFixtureV1,
};
#[cfg(test)]
use fixture_ports::VirtualCompletionScriptV1;
pub use gocode_platform::process_contract::ProcessPlatformTargetV1;
pub use gocode_platform_ports::process::{
    HeldFileIdentityV1, HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessFileKindV1,
    ProcessGenerationIdV1, ProcessLifecycleBindingV1, ProcessOwnerIdV1, ProcessSessionIdV1,
    ProcessStubDisposition, ProcessSymlinkProofV1, VerifiedCwdV1, VerifiedExecutableV1,
};
pub use gocode_platform_ports::process::{ProcessOwnerVerificationV1, ProcessTreeCleanupV1};
pub use gocode_security::process_contract::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    ExecutablePolicyId, ExplicitEnvironmentV1, InputBoundsV1, PortableUtf8V1, PrincipalId,
    ProcessApprovalV1, ProcessAuthorizationAdvanceV1, ProcessAuthorizationAuthorityV1,
    ProcessAuthorizationBoundaryV1, ProcessCapabilityId, ProcessCapabilityV1, ProcessContractError,
    ProcessIdentityBindingV1, ProcessIntentDigestV1, ProcessIntentV1, ProcessIoBoundsV1, SandboxId,
    StdinPolicyV1, ValidatedProcessIntentV1,
};
pub use host::{ProcessContractHostSnapshotV1, ProcessContractHostV1, ProcessHostOutcomeV1};
pub use journal_memory::{ProcessClaimJournalMemorySnapshotV1, ProcessClaimJournalMemoryV1};
pub use lifecycle::ProcessLifecycleStateV1;
pub(crate) use orchestrator::{
    ProcessCancellationTokenV1, ProcessDispatchOutcomeV1, ProcessMonotonicClockV1,
    ProcessOrchestratorV1,
};
pub use output::{
    ProcessCancellationDispositionV1, ProcessOutputBoundsV1, ProcessOutputCaptureErrorV1,
    ProcessOutputChannelEvidenceV1, ProcessOutputEvidenceV1, ProcessOutputSourceErrorV1,
    ProcessOutputSourceViolationV1, ProcessOutputStopEvidenceV1,
};
pub(crate) use output::{
    ProcessOutputCallerIdV1, ProcessOutputCollectorV1, ProcessOutputReadBudgetV1,
    ProcessOutputSourceEventV1, ProcessOutputSourcePortV1, ProcessOutputStopReasonV1,
    ProcessOutputStreamV1, TransientProcessOutputChannelV1,
};
pub use settlement::{
    ProcessMonotonicTimingDispositionV1, ProcessSettlementProofV1, ProcessTerminalResultV1,
    ProcessTerminalSettlementV1, ProcessUncertainReasonV1,
};

/// Object-safe sandbox qualification gate for process admission.
pub trait SandboxQualificationProbe: Send + Sync {
    /// Qualifies the sandbox or returns its closed failure disposition without an effect.
    fn qualify(&self) -> Result<(), ProcessStubDisposition>;
}

struct ProductionSandboxProbe {
    _linux_stub: gocode_platform::process_contract::ProcessPlatformStubV1,
}

impl SandboxQualificationProbe for ProductionSandboxProbe {
    fn qualify(&self) -> Result<(), ProcessStubDisposition> {
        Err(ProcessStubDisposition::NotQualified)
    }
}

/// Creates the only production probe, backed by a closed not-qualified stub.
#[must_use]
pub fn production_sandbox_probe() -> impl SandboxQualificationProbe {
    ProductionSandboxProbe {
        _linux_stub: gocode_platform::process_contract::ProcessPlatformStubV1::for_target(
            ProcessPlatformTargetV1::Linux,
        ),
    }
}
