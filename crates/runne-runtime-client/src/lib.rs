//! Runtime transport and schema bundle verification.
//!
//! The canonical schema bundle (`gocode-ui-client/2`) is generated
//! byte-for-byte by the runtime contract generator. This module verifies the
//! exact content-only bundle digest independently from release source evidence.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

mod canonical;
mod local_profile;
mod local_session;
mod replay;
mod sse;

pub use canonical::CommandReconciliationOutcome;
pub use canonical::{
    APPROVALS_CAPABILITY_V1, ApprovalDecisionAcknowledgementDto, ApprovalDecisionDto,
    ApprovalDecisionRequest, ApprovalStateDto, ApprovalSummaryDto, AuthenticatedRuntimeClient,
    CancelTaskRunRequest, CanonicalId, CommandIdentity, ConversationCreated, ConversationMessage,
    ConversationMessageRole, ConversationMessages, ConversationTextResult,
    CreateConversationRequest, ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES, EditorLaunchReceiptDto,
    EditorLaunchTargetDto, GenerateTextRequest, OpenEditorCommandRequest,
    PROCESS_CONTROL_CAPABILITY_V1, PROTECTED_RUNTIME_CAPABILITIES,
    PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2, ProcessOutputChunkDto, ProcessOutputPageDto,
    ProcessOutputStreamDto, ProcessSnapshotDto, ProcessStateDto, REQUIRED_RUNTIME_CAPABILITIES,
    RuntimeApiError, RuntimeApiErrorKind, RuntimeSessionAuthority, RuntimeSessionInfo,
    RuntimeTransportKind, StartProcessRequest, StopProcessRequest, SubmitTaskRunRequest,
    TaskRunCancellationAcknowledgement, TaskRunSnapshot, TaskRunState,
    TaskRunSubmitAcknowledgement, TaskRunTerminalResult, WORKSPACE_DIFFS_CAPABILITY_V1,
    WORKSPACE_EDITOR_CAPABILITY_V1, WORKSPACE_FILES_CAPABILITY_V1, WorkspaceChangeEntryDto,
    WorkspaceChangeKindDto, WorkspaceChangeSetDto, WorkspaceDiffDto, WorkspaceDiffHunkDto,
    WorkspaceDiffLineDto, WorkspaceDiffLineKindDto, WorkspaceFileContentDto, WorkspaceFileEntryDto,
    WorkspaceFileKindDto, WorkspaceFilePageDto, protected_profile_matches,
};
pub use canonical::{
    BindWorkspaceRootRequest, CreateProjectRequest, CreateWorkspaceRequest, ExistingProjectRequest,
    ExistingWorkspaceRequest, ProjectCommandAcknowledgement, ProjectPageCursor, ProjectPageDto,
    ProjectSnapshotDto, ProtectedRootAdmission, RenameProjectRequest,
    WorkspaceCommandAcknowledgement, WorkspacePageCursor, WorkspacePageDto, WorkspaceSnapshotDto,
};
pub use canonical::{CommandReconciliationDisposition, CommandReconciliationRequest};
pub use canonical::{ConversationGenerationFailureReason, ConversationTextRejection};
pub use canonical::{
    PairProviderCredentialRequest, ProviderCredentialMutationAckDto,
    RevokeProviderCredentialRequest,
};
pub use local_profile::{
    LocalProfileError, LocalRuntimeConnectError, LocalRuntimeProfile, default_local_profile_path,
};
pub use local_session::ProtectedBundledRuntimeProfile;
pub use replay::{
    CanonicalReplayEvent, CanonicalReplayPayload, ConversationReplayPayload, LiveDeliveryId,
    ReconnectDecision, ReconnectPolicy, ReconnectRuntime, ReplayAggregateKind,
    ReplayBaselineVerificationError, ReplayClientError, ReplayClientErrorKind, ReplayCursor,
    ReplayDelivery, ReplayDeliveryDisposition, ReplayIdentityTracker, ReplayLiveSession,
    ReplayPendingBaselineResume, ReplayPersistenceBinding, ReplayPersistenceHandoff,
    ReplayRecoveryDisposition, ReplayRetentionBaselineV1, ReplayRetentionBaselineV2, ReplayScope,
    ReplaySensitivity, ReplaySessionId, ReplayStreamEvent, ReplayTerminal, ReplayTerminalCode,
    TaskRunReplayPayload, TaskRunTimelineKind, replay_persistence_digest,
};
pub use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialOperationHandleV2, ProviderCredentialOperationKindV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialProviderV2,
    ProviderCredentialSafeSnapshotV2, ProviderCredentialVerificationKindV2,
    VerifyProviderCredential,
};
pub use runne_api::{
    ExpiryAggregateV1, MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1,
    OPERATIONAL_TELEMETRY_CAPABILITY_V1, OPERATIONAL_TELEMETRY_SCHEMA_VERSION_V1,
    RecoveryObservationStatusV1, RuntimeBudgetV1, RuntimeDurableAccountingV1,
    RuntimeDurableOperationalTelemetryV1, RuntimeOperationalTelemetrySnapshotV1,
    RuntimeRecoveryTransientV1, TelemetryCompletenessV1, TelemetryFreshnessV1,
    TelemetrySectionMetaV1,
};
pub use sse::{MAXIMUM_SSE_FRAME_BYTES, SSE_SILENCE_TIMEOUT};

include!("lib_parts/mock_transport.rs");
include!("lib_parts/transport.rs");
include!("lib_parts/health.rs");

#[cfg(test)]
mod tests {
    include!("lib_parts/tests.rs");
}
