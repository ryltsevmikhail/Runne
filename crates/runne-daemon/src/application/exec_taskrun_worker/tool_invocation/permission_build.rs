use super::*;
use runne_application::permission_modes::{
    ChildDelegationScope, CompositeEffectScope, EffectBudget, FilesystemPermission,
    FilesystemPosture, FilesystemRoot, FilesystemScope, ManagedPolicyCoverage, NetworkScope,
    PermissionAction, PermissionMode, PermissionScope,
};
use runne_application::ports::TaskRunAssignmentIdentity;
use runne_application::project_trust::ProjectTrustProjectId;
use runne_domain::id::IntegrityDigest;
use runne_platform::local_command_linux::LinuxCompositeScopeAdmission;
use runne_platform_desktop::LinuxCommandWorkspaceFiles;
use runne_store::store::{
    PermissionModeSelectionSnapshot, taskrun_tool_invocation::ToolInvocationBindingV1,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) fn helper_binding(
    binding: &ToolInvocationBindingV1,
    assignment: &TaskRunAssignmentIdentity,
) -> Result<crate::safe_tool_helper::BindingV1, ()> {
    Ok(crate::safe_tool_helper::BindingV1 {
        taskrun_id: binding.key.taskrun_id.to_string(),
        attempt_id: binding.key.attempt_id.to_string(),
        cycle_id: binding.key.cycle_id.to_string(),
        proposal_index: binding.key.proposal_index,
        taskrun_version: binding.expected_taskrun_version,
        assignment_fence: assignment.fence.0,
        invocation_digest: binding.semantic_digest.to_string(),
        environment_digest: format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{}\0{}",
                    binding.environment_id, binding.environment_revision
                )
                .as_bytes()
            )
        ),
        approval_digest: binding.approval_digest.to_string(),
        expires_at_unix_ms: u64::try_from(binding.approval_expires_at).map_err(|_| ())?,
    })
}

pub(super) fn helper_request(
    binding: &ToolInvocationBindingV1,
    assignment: &TaskRunAssignmentIdentity,
    root: crate::safe_tool_helper::IdentityV1,
    target: Option<crate::safe_tool_helper::VersionV1>,
    content: &[u8],
) -> Result<Vec<u8>, ()> {
    if binding.environment_id == crate::safe_tool_helper::coding_arguments::ENVIRONMENT {
        let request = crate::safe_tool_helper::RequestV1::Coding {
            binding: helper_binding(binding, assignment)?,
            tool_name: binding.tool_name.clone(),
            arguments: serde_json::from_slice(&binding.canonical_arguments).map_err(|_| ())?,
            root,
            expected: target,
        };
        let bytes = serde_json::to_vec(&request).map_err(|_| ())?;
        return (bytes.len() <= 16384).then_some(bytes).ok_or(());
    }
    crate::safe_tool_helper::encode_request(
        helper_binding(binding, assignment)?,
        binding.target_name.clone(),
        root,
        target,
        content,
    )
}

pub(super) struct ProposalRootCapture {
    pub files: LinuxCommandWorkspaceFiles,
    pub workspace_version: u64,
    pub root_revision: u64,
    pub root_identity: [u8; 32],
    pub trust: runne_application::project_trust::TrustToken,
    pub target_digest: Option<IntegrityDigest>,
    pub target_version: Option<crate::safe_tool_helper::VersionV1>,
    pub root_file_identity: crate::safe_tool_helper::IdentityV1,
    pub project_id: [u8; 16],
}

pub(super) fn capture_proposal_root(
    root_admission: &crate::application::root_handle_admission::RootAdmissionGateway,
    workspace_id: runne_domain::id::WorkspaceId,
    tool_name: &str,
    path: &str,
    coding: bool,
) -> Result<ProposalRootCapture, ()> {
    use crate::application::exec_taskrun_worker::local::run::tool_executor as executor;
    root_admission
        .with_local_command_root(workspace_id, |root, wv, project_id, rv, ri, admission| {
            let files = root.open_linux_command_workspace(std::path::Path::new("."))?;
            let (device, inode) = executor::descriptor_identity(files.workspace())
                .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Unavailable)?;
            let target_version = if coding {
                crate::safe_tool_helper::coding_fs::capture(files.workspace(), tool_name, path)
                    .map_err(|_| ())
            } else {
                executor::capture_target_precondition(&files, tool_name, path)
            }
            .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)?;
            let target_digest = target_version.as_ref().map(|value| {
                IntegrityDigest::from_bytes(
                    Sha256::digest(serde_json::to_vec(value).expect("version serializes")).into(),
                )
            });
            Ok(ProposalRootCapture {
                files,
                workspace_version: wv,
                root_revision: rv,
                root_identity: ri,
                trust: admission.token,
                target_digest,
                target_version,
                root_file_identity: crate::safe_tool_helper::IdentityV1 { device, inode },
                project_id,
            })
        })
        .map_err(|_| ())
}

#[expect(
    clippy::too_many_arguments,
    reason = "These independently validated bindings are passed explicitly to helper preparation."
)]
pub(super) fn prepare_tool_helper(
    store: &runne_store::store::StoreTransaction,
    prepared: &super::permission::PreparedPermissionInvocation,
    binding: &ToolInvocationBindingV1,
    assignment: &TaskRunAssignmentIdentity,
    root: crate::safe_tool_helper::IdentityV1,
    target: Option<crate::safe_tool_helper::VersionV1>,
    content: &[u8],
    files: LinuxCommandWorkspaceFiles,
) -> Result<(), ()> {
    let request = helper_request(binding, assignment, root, target, content)?;
    let preparation = store.local_permission_preparation().map_err(|_| ())?;
    let helper = preparation
        .prepare_tool_helper(
            prepared.scope.clone(),
            prepared.native_receipt,
            &request,
            files.workspace(),
            files.cwd(),
        )
        .map_err(|_| ())?;
    prepared.attach_helper(helper)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn invocation_scope(
    managed_policy: ManagedPolicyCoverage,
    runtime_authority: &str,
    principal: &ApiPrincipalId,
    workspace_id: runne_domain::id::WorkspaceId,
    root_identity: IntegrityDigest,
    binding: &ToolInvocationBindingV1,
    native: &LinuxCompositeScopeAdmission,
) -> Result<CompositeEffectScope, ()> {
    let root = FilesystemRoot::new(root_identity, Vec::new()).map_err(|_| ())?;
    let mut permissions = BTreeSet::new();
    match action(binding) {
        PermissionAction::FsRead => {
            permissions.insert(FilesystemPermission::Read);
        }
        PermissionAction::FsWrite => {
            permissions.extend([FilesystemPermission::Read, FilesystemPermission::Write]);
        }
        PermissionAction::ProcessStart => {
            permissions.extend([
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]);
        }
        PermissionAction::FsCreate => {
            permissions.extend([
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
            ]);
        }
        _ => return Err(()),
    }
    Ok(CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: runne_application::ports::RuntimeAuthorityId(
                runtime_authority.to_owned(),
            ),
            principal_id: principal.clone(),
            workspace_id,
        },
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BoundedRoots(BTreeSet::from([root])),
            permissions,
        },
        network: NetworkScope::None,
        managed_policy,
        children: if action(binding) == PermissionAction::ProcessStart {
            ChildDelegationScope::Unbounded
        } else {
            ChildDelegationScope::None
        },
        budget: EffectBudget {
            max_operations: Some(1),
            max_bytes: if action(binding) == PermissionAction::ProcessStart {
                None
            } else {
                Some(8192)
            },
        },
        lifetime_ms: 120_000,
        containment: runne_application::permission_modes::ContainmentStrategy::WorkspaceBoundV1,
        protected_control_plane_policy_digest: native.protected_control_plane_policy_digest(),
    })
}

pub(super) fn effective_scope(
    snapshot: &PermissionModeSelectionSnapshot,
    invocation: &CompositeEffectScope,
    trust_project: ProjectTrustProjectId,
    trust_snapshot: &runne_application::project_trust::ProjectTrustEffectPolicySnapshot,
    _native: &LinuxCompositeScopeAdmission,
) -> Result<CompositeEffectScope, ()> {
    if snapshot.selection.selected_mode != PermissionMode::FullAccess {
        return Ok(invocation.clone());
    }
    let mut scope = invocation.clone();
    let permissions = [
        FilesystemPermission::Read,
        FilesystemPermission::Create,
        FilesystemPermission::Write,
        FilesystemPermission::Delete,
    ]
    .into_iter()
    .collect();
    scope.filesystem = FilesystemScope {
        posture: FilesystemPosture::BroadSameUser,
        permissions,
    };
    scope.network = NetworkScope::BroadSameUser;
    scope.children = ChildDelegationScope::Unbounded;
    scope.managed_policy =
        ManagedPolicyCoverage::from_closed_snapshot(trust_project, trust_snapshot).ok_or(())?;
    scope.budget = EffectBudget {
        max_operations: None,
        max_bytes: None,
    };
    scope.containment =
        runne_application::permission_modes::ContainmentStrategy::SameUserCompositeV1;
    Ok(scope)
}

pub(super) use super::permission_identity::{action, approval_binding, resource_facts};
