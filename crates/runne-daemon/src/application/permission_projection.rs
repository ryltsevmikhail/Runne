use runne_api::ApiPrincipalId;
use runne_application::{
    permission_modes::{
        ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, EffectBudget,
        EffectiveModeState, FilesystemPermission, FilesystemPosture, FilesystemScope,
        ManagedPolicyCoverage, ModeSelection, NativeScopeAdmissionPort, NetworkScope, NetworkState,
        NotReadyReason, PermissionMode, PermissionModeProjection, PermissionScope,
        admit_effective_mode,
    },
    project_trust::{ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId},
};
use runne_domain::id::{IntegrityDigest, WorkspaceId};

use super::root_handle_admission::RootAdmissionGateway;
use runne_store::{
    ProjectWorkspaceStore,
    store::{ProtectedNativeLaunchContext, StoreTransaction},
};

// Public status and commit history are released for the final D2.1 activation.
const CURRENT_PROJECTION_RELEASED: bool = true;

#[derive(Clone)]
pub(crate) struct ProjectionMetadata {
    pub(crate) selection: ModeSelection,
    pub(crate) managed_policy_version: u64,
}

pub(crate) struct ProjectionObservation {
    pub(crate) effective: EffectiveModeState,
    pub(crate) containment: Option<ContainmentStrategy>,
    pub(crate) network_state: NetworkState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingApprovalScopeUnavailable;

pub(crate) fn pending_ids_for_workspace(
    approvals: Vec<runne_api::ApprovalSummary>,
    workspace: WorkspaceId,
    mut task_run_workspace: impl FnMut(
        runne_domain::id::TaskRunId,
    )
        -> Result<Option<WorkspaceId>, PendingApprovalScopeUnavailable>,
) -> Result<Vec<runne_domain::id::ApprovalId>, PendingApprovalScopeUnavailable> {
    let mut pending = Vec::new();
    for approval in approvals {
        if task_run_workspace(approval.task_run_id())? == Some(workspace) {
            pending.push(approval.approval_id());
        }
    }
    Ok(pending)
}

/// Shared public entry for status and immutable commit history.
/// The closed release gate returns before running `probe`.
pub(crate) fn current_projection(
    metadata: ProjectionMetadata,
    probe: impl FnOnce() -> Result<ProjectionObservation, NotReadyReason>,
) -> PermissionModeProjection {
    if !CURRENT_PROJECTION_RELEASED {
        return not_ready(metadata, NotReadyReason::NativeContainment);
    }
    match probe() {
        Ok(observation) => PermissionModeProjection {
            selected_mode: metadata.selection.selected_mode,
            effective: observation.effective,
            authorization_revision: metadata.selection.authorization_revision,
            preset_version: metadata.selection.preset_version,
            managed_policy_version: metadata.managed_policy_version,
            pending_approval_ids: Vec::new(),
            containment: observation.containment,
            network_state: observation.network_state,
            expires_at_unix_ms: metadata.selection.expires_at_unix_ms,
        },
        Err(reason) => not_ready(metadata, reason),
    }
}

fn not_ready(metadata: ProjectionMetadata, reason: NotReadyReason) -> PermissionModeProjection {
    PermissionModeProjection {
        selected_mode: metadata.selection.selected_mode,
        effective: EffectiveModeState::NotReady(reason),
        authorization_revision: metadata.selection.authorization_revision,
        preset_version: metadata.selection.preset_version,
        managed_policy_version: metadata.managed_policy_version,
        pending_approval_ids: Vec::new(),
        containment: None,
        network_state: NetworkState::Unavailable,
        expires_at_unix_ms: metadata.selection.expires_at_unix_ms,
    }
}

/// Shared stateless scope builder used by the worker and current projection.
pub(crate) fn local_command_scope(
    selection: &ModeSelection,
    permission_scope: PermissionScope,
    project: ProjectTrustProjectId,
    trust: &ProjectTrustEffectPolicySnapshot,
    protected_control_plane_policy_digest: IntegrityDigest,
) -> Result<CompositeEffectScope, NotReadyReason> {
    let network = if selection.selected_mode == PermissionMode::FullAccess {
        NetworkScope::BroadSameUser
    } else {
        NetworkScope::None
    };
    let managed_policy = ManagedPolicyCoverage::from_closed_snapshot(project, trust)
        .ok_or(NotReadyReason::CompositePolicyUnenforceable)?;
    Ok(CompositeEffectScope {
        permission_scope,
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BroadSameUser,
            permissions: [
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]
            .into_iter()
            .collect(),
        },
        network,
        managed_policy,
        children: ChildDelegationScope::Unbounded,
        budget: EffectBudget {
            max_operations: None,
            max_bytes: None,
        },
        lifetime_ms: 120_000,
        containment: ContainmentStrategy::SameUserCompositeV1,
        protected_control_plane_policy_digest,
    })
}

/// Computes effective-mode readiness without acquiring invocation authority.
pub(crate) fn observe_scope(
    selection: &ModeSelection,
    scope: &CompositeEffectScope,
    admission: &dyn NativeScopeAdmissionPort,
    now_unix_ms: i64,
) -> Result<ProjectionObservation, NotReadyReason> {
    if selection
        .expires_at_unix_ms
        .is_some_and(|expiry| expiry <= now_unix_ms)
    {
        return Err(NotReadyReason::NativeContainment);
    }
    let effective = admit_effective_mode(
        selection.selected_mode,
        selection.preset_version,
        scope,
        admission,
    )
    .map_err(|error| match error {
        runne_application::permission_modes::NativeAdmissionError::EnforcementUnavailable => {
            NotReadyReason::NativeContainment
        }
        runne_application::permission_modes::NativeAdmissionError::CompositePolicyUnenforceable => {
            NotReadyReason::CompositePolicyUnenforceable
        }
    })?;
    let containment = match &effective {
        EffectiveModeState::Ready(_) => Some(scope.containment),
        EffectiveModeState::NotReady(reason) => return Err(*reason),
    };
    Ok(ProjectionObservation {
        effective,
        containment,
        network_state: match scope.network {
            NetworkScope::BroadSameUser => NetworkState::BroadSameUser,
            NetworkScope::None => NetworkState::Unavailable,
            _ => return Err(NotReadyReason::CompositePolicyUnenforceable),
        },
    })
}

#[derive(Clone)]
pub(crate) enum ProjectionTarget {
    Current {
        selection: ModeSelection,
        managed_policy_version: u64,
    },
    Candidate {
        selection: ModeSelection,
        expected_revision: u64,
        managed_policy_version: u64,
        managed_policy_digest: IntegrityDigest,
    },
}

/// Rechecks current root, trust, managed identity and selection around a readiness probe.
#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_current_target(
    store: &StoreTransaction,
    workspaces: &ProjectWorkspaceStore,
    root: &RootAdmissionGateway,
    principal: &ApiPrincipalId,
    workspace: WorkspaceId,
    launch: &ProtectedNativeLaunchContext,
    target: &ProjectionTarget,
) -> Result<ProjectionObservation, NotReadyReason> {
    super::permission_projection_runtime::observe_current_target(
        store, workspaces, root, principal, workspace, launch, target,
    )
}

#[cfg(test)]
#[path = "permission_projection_tests.rs"]
mod tests;
