use std::sync::atomic::{AtomicUsize, Ordering};

use runne_api::{ApiPrincipalId, ApprovalSummary};
#[cfg(target_os = "linux")]
use runne_application::ports::ProjectWorkspaceRepository;
use runne_application::{
    permission_modes::{
        CompositeEffectScope, ContainmentStrategy, EffectiveModeState, ModeSelection,
        NativeAdmissionError, NativeScopeAdmissionPort, NetworkScope, NetworkState, NotReadyReason,
        PermissionMode, PermissionScope, PresetVersion,
    },
    ports::RuntimeAuthorityId,
    project_trust::{
        ManagedEffectPolicyV1, ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId,
        ProjectTrustRecord, ProjectTrustStatus,
    },
};
use runne_domain::id::{ApprovalId, IntegrityDigest, InvocationId, TaskRunId, WorkspaceId};
#[cfg(target_os = "linux")]
use runne_domain::{
    id::{CommandId, IdempotencyKey, ProjectId},
    project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace},
};
#[cfg(target_os = "linux")]
use runne_store::store::{
    ClosedRulesManagedIdentityV2, ManagedIdentityMetadata, PermissionModeSelectionManagedIdentity,
};
#[cfg(target_os = "linux")]
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};

use super::{
    ProjectionMetadata, ProjectionTarget, current_projection, local_command_scope, observe_scope,
    pending_ids_for_workspace,
};

#[path = "permission_projection_tests/fakes.rs"]
mod fakes;
#[path = "permission_projection_tests/gate_tests.rs"]
mod gate_tests;
#[path = "permission_projection_tests/pending_tests.rs"]
mod pending_tests;

use fakes::*;
