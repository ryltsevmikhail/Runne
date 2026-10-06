use super::*;
use runne_application::permission_modes::{
    ApprovalBinding, ChildDelegationScope, CompositeEffectScope, EffectBudget,
    FilesystemPermission, FilesystemPosture, FilesystemRoot, FilesystemScope, InvocationIdentity,
    ManagedPolicyCoverage, NetworkScope, ObjectKind, PermissionAction, PermissionMode,
    PermissionScope, ResolutionState, ResourceFacts, Sensitivity, SizeBound, TargetState,
    WorkspaceRelation,
};
use runne_domain::id::IntegrityDigest;
use runne_platform::local_command_linux::LinuxCompositeScopeAdmission;
use runne_store::store::{
    PermissionModeSelectionSnapshot, taskrun_tool_invocation::ToolInvocationBindingV1,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[allow(clippy::too_many_arguments)]
pub(super) fn invocation_scope(
    snapshot: &PermissionModeSelectionSnapshot,
    runtime_authority: &str,
    principal: &ApiPrincipalId,
    workspace_id: runne_domain::id::WorkspaceId,
    root_identity: IntegrityDigest,
    binding: &ToolInvocationBindingV1,
    native: &LinuxCompositeScopeAdmission,
) -> Result<CompositeEffectScope, ()> {
    let root = FilesystemRoot::new(root_identity, Vec::new()).map_err(|_| ())?;
    let mut permissions = BTreeSet::new();
    permissions.insert(match action(binding) {
        PermissionAction::FsRead => FilesystemPermission::Read,
        PermissionAction::FsCreate => FilesystemPermission::Create,
        _ => return Err(()),
    });
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
        managed_policy: ManagedPolicyCoverage::Unrestricted {
            policy_digest: snapshot.managed_policy_digest,
        },
        children: ChildDelegationScope::None,
        budget: EffectBudget {
            max_operations: Some(1),
            max_bytes: Some(8192),
        },
        lifetime_ms: 120_000,
        containment: runne_application::permission_modes::ContainmentStrategy::WorkspaceBoundV1,
        protected_control_plane_policy_digest: native.protected_control_plane_policy_digest(),
    })
}

pub(super) fn effective_scope(
    snapshot: &PermissionModeSelectionSnapshot,
    invocation: &CompositeEffectScope,
) -> Result<CompositeEffectScope, ()> {
    if snapshot.selection.selected_mode != PermissionMode::FullAccess {
        return Ok(invocation.clone());
    }
    let mut scope = invocation.clone();
    let mut permissions = BTreeSet::new();
    permissions.insert(FilesystemPermission::Read);
    permissions.insert(FilesystemPermission::Create);
    permissions.insert(FilesystemPermission::Write);
    permissions.insert(FilesystemPermission::Delete);
    scope.filesystem = FilesystemScope {
        posture: FilesystemPosture::BroadSameUser,
        permissions,
    };
    scope.network = NetworkScope::BroadSameUser;
    scope.children = ChildDelegationScope::Unbounded;
    scope.budget.max_bytes = None;
    scope.containment =
        runne_application::permission_modes::ContainmentStrategy::SameUserCompositeV1;
    Ok(scope)
}

pub(super) fn approval_binding(
    snapshot: &PermissionModeSelectionSnapshot,
    principal: &ApiPrincipalId,
    scope: &CompositeEffectScope,
    binding: &ToolInvocationBindingV1,
) -> ApprovalBinding {
    let mut target = Sha256::new();
    target.update(b"RUNNE_D2_TARGET_IDENTITY_V1\0");
    target.update(binding.root_identity.as_bytes());
    target.update(
        binding
            .target_precondition
            .map_or([0; 32], |v| *v.as_bytes()),
    );
    ApprovalBinding {
        action: action(binding),
        normalized_arguments_digest: binding.arguments_digest,
        tool_schema_digest: binding.schema_digest,
        principal_id: principal.clone(),
        invocation: InvocationIdentity {
            task_run_id: binding.key.taskrun_id,
            attempt_id: binding.key.attempt_id,
            invocation_id: runne_domain::id::InvocationId::from_bytes(binding.approval_id),
        },
        target_identity_digest: IntegrityDigest::from_bytes(target.finalize().into()),
        target_version: binding.root_revision,
        environment_digest: environment_digest(binding),
        cwd_identity_digest: binding.root_identity,
        executable_digest: None,
        composite_scope_digest: scope.digest().expect("validated invocation scope"),
        containment_version: scope.containment,
        relevant_policy_digest: snapshot.managed_policy_digest,
        expires_at_unix_ms: binding.approval_expires_at,
    }
}

pub(super) fn action(binding: &ToolInvocationBindingV1) -> PermissionAction {
    match binding.tool_name.as_str() {
        "workspace.file.read" => PermissionAction::FsRead,
        "workspace.file.create_new" => PermissionAction::FsCreate,
        // The D2 tool schema is closed over exactly these two declarations;
        // an unknown name must fail closed instead of silently receiving a
        // mutating-operation classification.
        _ => unreachable!("closed D2 tool schema admits only read and create_new"),
    }
}

pub(super) fn resource_facts(binding: &ToolInvocationBindingV1) -> ResourceFacts {
    let create = binding.tool_name == "workspace.file.create_new";
    ResourceFacts {
        workspace: WorkspaceRelation::Inside,
        sensitivity: Sensitivity::Nonsensitive,
        size: SizeBound::Bounded,
        resolution: ResolutionState::HeldSafe,
        resolved_path: Some(
            FilesystemRoot::new(binding.root_identity, vec![binding.target_name.clone()])
                .expect("D2 target is canonical"),
        ),
        target: if create {
            TargetState::Absent
        } else {
            TargetState::Existing
        },
        object: ObjectKind::RegularFile,
        executable: false,
    }
}

fn environment_digest(binding: &ToolInvocationBindingV1) -> IntegrityDigest {
    let mut hash = Sha256::new();
    hash.update(b"RUNNE_D2_ENVIRONMENT_V1\0");
    hash.update(binding.environment_id.as_bytes());
    hash.update(binding.environment_revision.as_bytes());
    IntegrityDigest::from_bytes(hash.finalize().into())
}
