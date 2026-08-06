#![cfg_attr(not(test), allow(dead_code, unused_imports))]

//! Marker-safe process claim projection and closed lifecycle contracts.
//!
//! Dispatch composition is crate-private and intentionally unwired. A sealed
//! cross-crate runtime host remains deferred; this crate exposes no host mint,
//! closure, or feature for it.

mod claim;
mod control;
mod error;
mod evidence;
#[cfg(test)]
mod fixture;
#[cfg(test)]
mod fixture_ports;
mod journal;
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
pub use gocode_platform_ports::process::{ProcessOwnerVerificationV1, ProcessTreeCleanupV1};
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
