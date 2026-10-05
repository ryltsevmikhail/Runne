//! Platform-neutral application orchestration.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use runne_api::ProviderStatusSnapshotV1;
use runne_local_store::{
    LocalStore, ProjectOpenError, RecentRoot, RecentRootError, ReplayScopeKey,
    SecurityTransactionError, StoreOpenError,
};
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use runne_runtime_client::test_decode_task_run_effects_wire;
pub use runne_runtime_client::{ApprovalDecisionDto, CanonicalId};
use runne_runtime_client::{
    AuthenticatedRuntimeClient, CommandIdentity, CreateConversationRequest, CreateProjectRequest,
    CreateWorkspaceRequest, ExistingProjectRequest, ExistingWorkspaceRequest, GenerateTextRequest,
    LocalProfileError, LocalRuntimeConnectError, LocalRuntimeProfile, ProcessOutputPageDto,
    ProcessOutputStreamDto, ProcessSnapshotDto, ProcessStateDto, ReconnectDecision,
    ReconnectPolicy, ReplayAggregateKind, ReplayClientError, ReplayIdentityTracker,
    ReplayRecoveryDisposition, ReplayScope, ReplayStreamEvent, RuntimeApiErrorKind,
    RuntimeOperationalTelemetrySnapshotV1, RuntimeTransportKind, StartProcessRequest,
    StopProcessRequest, TaskRunState, TelemetryCompletenessV1, TelemetryFreshnessV1,
    TelemetrySectionMetaV1, WorkspaceChangeEntryDto, WorkspaceChangeKindDto, WorkspaceDiffDto,
    WorkspaceDiffHunkDto, WorkspaceDiffLineDto, WorkspaceDiffLineKindDto, WorkspaceFileEntryDto,
    WorkspaceFileKindDto, default_local_profile_path,
};
pub use runne_runtime_client::{
    LocalCommandEffect, LocalExecutionOutcome, LocalStopEvidence, RemoteAccountingDisposition,
    RemoteCancellationEvidence, RemoteEffect, RemoteEffectAvailability, RemoteEffectCapabilities,
    RemoteEffectOutcome, RemotePublicationDisposition, TaskRunCancellationAcknowledgement,
    TaskRunEffectsV1, TaskRunSuccessorAcknowledgement, TaskRunSuccessorEligibility,
    UnknownSuccessorAcknowledgment,
};
pub use runne_runtime_client::{
    ProjectTrustControlRequestDto, ProjectTrustControlSnapshotDto, ProjectTrustDecisionDto,
    ProjectTrustStatusDto,
};
use runne_secure_store::SecureStore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod qualification_diagnostics;
mod replay;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

const RUNTIME_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONVERSATION_REFERENCE_SCHEMA_VERSION: u32 = 2;

include!("lib_parts/errors.rs");
include!("lib_parts/runtime.rs");
include!("lib_parts/snapshots.rs");
include!("lib_parts/core.rs");
include!("lib_parts/open.rs");
include!("lib_parts/production_open.rs");
include!("lib_parts/bundled.rs");
include!("lib_parts/connect.rs");
include!("lib_parts/subscribe.rs");
include!("lib_parts/projects.rs");
include!("lib_parts/project_trust_control.rs");
include!("lib_parts/settings.rs");
include!("lib_parts/shortcuts.rs");
include!("lib_parts/device.rs");
include!("lib_parts/providers.rs");
include!("lib_parts/provider_credential_enrollment.rs");
include!("lib_parts/files.rs");
include!("lib_parts/diffs.rs");
include!("lib_parts/processes.rs");
include!("lib_parts/editor.rs");
include!("lib_parts/runtime_state.rs");
include!("lib_parts/operational_telemetry.rs");
include!("lib_parts/operational_telemetry_events.rs");
include!("lib_parts/operational_telemetry_state.rs");
include!("lib_parts/operational_telemetry_snapshot.rs");
include!("lib_parts/conversation.rs");
include!("lib_parts/conversation_reference_owner.rs");
include!("lib_parts/conversation_workspace.rs");
include!("lib_parts/task_run.rs");
include!("lib_parts/task_run_count.rs");
include!("lib_parts/approvals.rs");
include!("lib_parts/task_run_subscribe.rs");
include!("lib_parts/reference.rs");
include!("lib_parts/mutation_types.rs");
include!("lib_parts/mutation_ledger_v7.rs");
include!("lib_parts/mutation_reconcile.rs");
include!("lib_parts/mutation_recovery.rs");
include!("lib_parts/mutation_store.rs");
include!("lib_parts/mutation_dispatch.rs");
include!("lib_parts/destructive_action.rs");
include!("lib_parts/mutation_conversation.rs");
include!("lib_parts/mutation_workspace.rs");
include!("lib_parts/bootstrap.rs");

#[cfg(test)]
mod tests {
    include!("lib_parts/tests.rs");
    include!("lib_parts/text_only_owner_tests.rs");
    include!("lib_parts/conversation_workspace_tests.rs");
    mod canonical_project_pagination_tests {
        include!("lib_parts/canonical_project_pagination_tests.rs");
    }
    include!("lib_parts/operational_telemetry_tests.rs");
    include!("lib_parts/mutation_dispatch_tests.rs");
    include!("lib_parts/text_only_dispatch_tests.rs");
    include!("lib_parts/mutation_adversarial_tests.rs");
    include!("lib_parts/mutation_workspace_tests.rs");
    include!("lib_parts/mutation_workspace_admission_tests.rs");
    include!("lib_parts/mutation_workspace_admission_lock_tests.rs");
    include!("lib_parts/mutation_workspace_open_tests.rs");
    include!("lib_parts/mutation_project_tests.rs");
    include!("lib_parts/mutation_capability_tests.rs");
    include!("lib_parts/mutation_reconciliation_tests.rs");
    include!("lib_parts/mutation_v7_transition_tests.rs");
    mod prohibited_input_transition_tests {
        include!("lib_parts/prohibited_input_transition_tests.rs");
    }
    include!("lib_parts/mutation_reconcile_state_tests.rs");
    include!("lib_parts/mutation_restart_recovery_tests.rs");
    include!("lib_parts/mutation_rename_tests.rs");
    include!("lib_parts/mutation_network_matrix_tests.rs");
    include!("lib_parts/task_run_unknown_successor_tests.rs");
    include!("lib_parts/mutation_network_state_tests.rs");
    include!("lib_parts/mutation_network_state_bind_tests.rs");
    include!("lib_parts/mutation_cancellation_tests.rs");
    include!("lib_parts/mutation_submit_tests.rs");
    include!("lib_parts/destructive_action_tests.rs");
    include!("lib_parts/production_open_tests.rs");
    include!("lib_parts/device_tests.rs");
    include!("lib_parts/providers_tests.rs");
    include!("lib_parts/provider_credential_enrollment_tests.rs");
    include!("lib_parts/managed_task_run_api_tests.rs");
    mod task_run_terminal_projection_tests {
        use crate::{
            AppCoreError, CanonicalId, TaskRunProjectionState, TaskRunRecoveryDisposition,
            TaskRunTerminalDisposition, ensure_authoritative_task_run_covers_replay,
            task_run_snapshot,
        };
        include!("lib_parts/task_run_terminal_projection_tests.rs");
    }
}
