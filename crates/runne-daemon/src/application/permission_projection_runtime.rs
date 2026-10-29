use runne_api::ApiPrincipalId;
use runne_application::permission_modes::NotReadyReason;
use runne_domain::id::WorkspaceId;
use runne_store::{
    ProjectWorkspaceStore,
    store::{ProtectedNativeLaunchContext, StoreTransaction},
};

use super::{
    permission_projection::{ProjectionObservation, ProjectionTarget},
    root_handle_admission::RootAdmissionGateway,
};

#[cfg(target_os = "linux")]
use super::permission_projection::{local_command_scope, observe_scope};
#[cfg(target_os = "linux")]
use runne_application::{
    permission_modes::{ModeSelection, NetworkScope, PermissionMode, PermissionScope},
    ports::ProjectWorkspaceRepository,
    project_trust::ProjectTrustProjectId,
};
#[cfg(target_os = "linux")]
use runne_domain::id::ProjectId;
#[cfg(target_os = "linux")]
use runne_store::store::PermissionModeAuthorityContext;
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Revalidates current ownership around the Store-owned native readiness port.
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
    #[cfg(target_os = "linux")]
    {
        observe_current_target_linux(
            store, workspaces, root, principal, workspace, launch, target,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            store, workspaces, root, principal, workspace, launch, target,
        );
        Err(NotReadyReason::NativeContainment)
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn observe_current_target_linux(
    store: &StoreTransaction,
    workspaces: &ProjectWorkspaceStore,
    root: &RootAdmissionGateway,
    principal: &ApiPrincipalId,
    workspace: WorkspaceId,
    launch: &ProtectedNativeLaunchContext,
    target: &ProjectionTarget,
) -> Result<ProjectionObservation, NotReadyReason> {
    let workspace_row = workspaces
        .get_workspace(principal.as_str(), workspace)
        .map_err(|_| NotReadyReason::NativeContainment)?;
    if !workspace_row.open_state() {
        return Err(NotReadyReason::NativeContainment);
    }
    let root_snapshot = root
        .with_local_command_root(
            workspace,
            |_, workspace_version, project_id, root_version, root_identity, admission| {
                Ok(RootSnapshot {
                    workspace_version,
                    project_id,
                    root_version,
                    root_identity,
                    trust_token: admission.token,
                })
            },
        )
        .map_err(|_| NotReadyReason::NativeContainment)?;
    if !workspace_binding_matches(
        workspace_row.version(),
        workspace_row.open_state(),
        *workspace_row.project_id().as_bytes(),
        (root_snapshot.workspace_version, root_snapshot.project_id),
    ) {
        return Err(NotReadyReason::NativeContainment);
    }
    let project = ProjectTrustProjectId::from_bytes(root_snapshot.project_id);
    let scope = PermissionScope {
        runtime_authority_id: store.runtime_authority_id().clone(),
        principal_id: principal.clone(),
        workspace_id: workspace,
    };
    let (current, trust_snapshot, selection) = {
        let lease = root
            .acquire_local_command_effect_lease(workspace, root_snapshot.trust_token)
            .map_err(|_| NotReadyReason::NativeContainment)?;
        let trust_snapshot = lease
            .snapshot()
            .map_err(|_| NotReadyReason::NativeContainment)?;
        let authority =
            PermissionModeAuthorityContext::new(principal, project, lease.as_ref(), Some(launch));
        let current = store
            .load_permission_mode_selection_with_managed_identity(&scope, principal, &authority)
            .map_err(|_| NotReadyReason::NativeContainment)?;
        let managed = closed_identity(&current)?;
        ensure_project_version(
            workspaces,
            principal,
            root_snapshot.project_id,
            managed.project_version,
        )?;
        if managed.project_id != root_snapshot.project_id || managed.snapshot != trust_snapshot {
            return Err(NotReadyReason::CompositePolicyUnenforceable);
        }
        let selection = selected_target(target, &current, managed)?;
        if !selection_is_live(&selection, now_unix_ms()) {
            return Err(NotReadyReason::NativeContainment);
        }
        (current, trust_snapshot, selection)
    };

    let preparation = store
        .local_permission_preparation()
        .map_err(|_| NotReadyReason::NativeContainment)?;
    let network = if selection.selected_mode == PermissionMode::FullAccess {
        NetworkScope::BroadSameUser
    } else {
        NetworkScope::None
    };
    let digest = preparation
        .protected_control_plane_policy_digest_v2(network)
        .map_err(|_| NotReadyReason::NativeContainment)?;
    let composite =
        local_command_scope(&selection, scope.clone(), project, &trust_snapshot, digest)?;
    let observation = observe_scope(
        &selection,
        &composite,
        preparation.invocation_scope_admission_port(),
        now_unix_ms(),
    )?;
    ensure_project_version(
        workspaces,
        principal,
        root_snapshot.project_id,
        closed_identity(&current)?.project_version,
    )?;

    let (workspace_version, project_id, root_version, root_identity, trust_token) = root
        .with_local_command_root(
            workspace,
            |_, workspace_version, project_id, root_version, root_identity, admission| {
                Ok((
                    workspace_version,
                    project_id,
                    root_version,
                    root_identity,
                    admission.token,
                ))
            },
        )
        .map_err(|_| NotReadyReason::NativeContainment)?;
    if !workspace_binding_matches(
        workspace_version,
        true,
        project_id,
        (root_snapshot.workspace_version, root_snapshot.project_id),
    ) || root_version != root_snapshot.root_version
        || root_identity != root_snapshot.root_identity
        || trust_token != root_snapshot.trust_token
    {
        return Err(NotReadyReason::NativeContainment);
    }
    let lease = root
        .acquire_local_command_effect_lease(workspace, root_snapshot.trust_token)
        .map_err(|_| NotReadyReason::NativeContainment)?;
    if lease
        .snapshot()
        .map_err(|_| NotReadyReason::NativeContainment)?
        != trust_snapshot
    {
        return Err(NotReadyReason::CompositePolicyUnenforceable);
    }
    let authority =
        PermissionModeAuthorityContext::new(principal, project, lease.as_ref(), Some(launch));
    let after = store
        .load_permission_mode_selection_with_managed_identity(&scope, principal, &authority)
        .map_err(|_| NotReadyReason::NativeContainment)?;
    if after.selection != current.selection || after.identity != current.identity {
        return Err(NotReadyReason::NativeContainment);
    }
    if !selection_is_live(&selection, now_unix_ms()) {
        return Err(NotReadyReason::NativeContainment);
    }
    Ok(observation)
}

#[cfg(target_os = "linux")]
pub(super) use super::permission_projection_targets::closed_identity;
#[cfg(target_os = "linux")]
pub(crate) use super::permission_projection_targets::selected_target;
pub(super) use super::permission_projection_targets::workspace_binding_matches;

#[cfg(target_os = "linux")]
fn selection_is_live(selection: &ModeSelection, now: i64) -> bool {
    selection
        .expires_at_unix_ms
        .is_none_or(|expiry| expiry > now)
}

#[cfg(target_os = "linux")]
pub(super) fn ensure_project_version(
    workspaces: &ProjectWorkspaceStore,
    principal: &ApiPrincipalId,
    project_id: [u8; 16],
    expected_version: u64,
) -> Result<(), NotReadyReason> {
    let project = workspaces
        .get_project(principal.as_str(), ProjectId::from_bytes(project_id))
        .map_err(|_| NotReadyReason::NativeContainment)?;
    if project.archived() || project.version() != expected_version {
        Err(NotReadyReason::NativeContainment)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct RootSnapshot {
    workspace_version: u64,
    project_id: [u8; 16],
    root_version: u64,
    root_identity: [u8; 32],
    trust_token: runne_application::project_trust::TrustToken,
}

#[cfg(target_os = "linux")]
fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
