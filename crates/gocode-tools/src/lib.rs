#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Runtime-neutral tool registry and execution gateway contracts.

mod executor;
mod gateway;
mod model;
mod output;
mod process;
mod process_contract;
mod registry;

pub use executor::{
    CompletionMode, EffectAdmission, NoTerminalCompletion, ProcessCompletion,
    ProcessToolExecutorPort, ProtocolCompletion, ProtocolToolExecutorPort, ToolExecutionHandle,
    ToolExecutorError, ToolExecutorPort,
};
pub use gateway::{
    GateStage, ToolAdmissionDecision, ToolAdmissionError, ToolAdmissionPort, ToolCancelDisposition,
    ToolCancelRequest, ToolCloseEvidence, ToolCloseRequest, ToolDispatchRequest, ToolGateway,
    ToolGatewayError, ToolProtocolCloseRequest, ToolTerminalDisposition,
};
pub use model::{
    InvalidToolDefinition, InvalidToolIdentity, SandboxProfile, ToolClass, ToolDefinition,
    ToolDispatchBinding, ToolId, ToolRef, ToolVersion, ToolsetSnapshot,
};
pub use output::{BlobRef, InvalidOutputContract, RawToolOutput, ToolOutput, ToolOutputBounds};
pub use process::{
    ProcessCloseMaterial, ProcessLifecycleReport, ProcessOperation, ProcessStartRequest,
    ProcessToolError, ProcessToolExecutor,
};
pub use process_contract::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    ExecutablePolicyId, ExplicitEnvironmentV1, HeldFileIdentityV1, HeldProcessTreeHandleV1,
    InputBoundsV1, PortableUtf8V1, PrincipalId, ProcessApprovalV1, ProcessAttemptIdV1,
    ProcessAuditRecordV1, ProcessAuditStageV1, ProcessAuthorizationAdvanceV1,
    ProcessAuthorizationAuthorityV1, ProcessAuthorizationBoundaryV1,
    ProcessCancellationDispositionV1, ProcessCapabilityId, ProcessCapabilityV1,
    ProcessClaimJournalMemorySnapshotV1, ProcessClaimJournalMemoryV1, ProcessContractError,
    ProcessContractErrorV1, ProcessContractHostSnapshotV1, ProcessContractHostV1,
    ProcessFileKindV1, ProcessGenerationIdV1, ProcessHostOutcomeV1, ProcessIdentityBindingV1,
    ProcessIntentDigestV1, ProcessIntentV1, ProcessIoBoundsV1, ProcessLifecycleBindingV1,
    ProcessLifecycleStateV1, ProcessMonotonicTimingDispositionV1, ProcessOutputBoundsV1,
    ProcessOutputCaptureErrorV1, ProcessOutputChannelEvidenceV1, ProcessOutputEvidenceV1,
    ProcessOutputSourceErrorV1, ProcessOutputSourceViolationV1, ProcessOutputStopEvidenceV1,
    ProcessOwnerIdV1, ProcessOwnerVerificationV1, ProcessPlatformTargetV1, ProcessSessionIdV1,
    ProcessSettlementProofV1, ProcessStubDisposition, ProcessSymlinkProofV1,
    ProcessTerminalResultV1, ProcessTerminalSettlementV1, ProcessTreeCleanupV1,
    ProcessUncertainReasonV1, SandboxId, SandboxQualificationProbe, StdinPolicyV1,
    ValidatedProcessIntentV1, VerifiedCwdV1, VerifiedExecutableV1, production_sandbox_probe,
};
pub use registry::{RegisterToolOutcome, ToolRegistry, ToolRegistryError};
