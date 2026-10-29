use super::*;
use runne_application::permission_modes::*;
use runne_domain::id::IntegrityDigest;
use runne_store::store::taskrun_tool_invocation::ToolInvocationBindingV1;

pub(super) fn approval_binding(
    principal: &ApiPrincipalId,
    scope: &CompositeEffectScope,
    binding: &ToolInvocationBindingV1,
    helper_executable: Option<IntegrityDigest>,
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
        executable_digest: helper_executable,
        composite_scope_digest: scope.digest().expect("validated invocation scope"),
        containment_version: scope.containment,
        relevant_policy_digest: scope.managed_policy.policy_digest(),
        expires_at_unix_ms: binding.approval_expires_at,
    }
}

pub(super) fn action(binding: &ToolInvocationBindingV1) -> PermissionAction {
    match binding.tool_name.as_str() {
        "workspace.file.read" | "workspace.files.list" | "workspace.files.search" => {
            PermissionAction::FsRead
        }
        "workspace.file.replace" => PermissionAction::FsWrite,
        "workspace.command.run" => PermissionAction::ProcessStart,
        "workspace.file.create_new" => PermissionAction::FsCreate,
        // The selected tool schema is closed;
        // an unknown name must fail closed instead of silently receiving a
        // mutating-operation classification.
        _ => unreachable!("tool name was validated against the selected schema"),
    }
}

pub(super) fn resource_facts(binding: &ToolInvocationBindingV1) -> ResourceFacts {
    let create = binding.tool_name == "workspace.file.create_new";
    ResourceFacts {
        workspace: WorkspaceRelation::Inside,
        sensitivity: Sensitivity::Nonsensitive,
        size: if binding.tool_name == "workspace.command.run" {
            SizeBound::Unbounded
        } else {
            SizeBound::Bounded
        },
        resolution: ResolutionState::HeldSafe,
        resolved_path: Some(
            FilesystemRoot::new(
                binding.root_identity,
                if binding.target_name == "." {
                    vec![]
                } else {
                    binding.target_name.split('/').map(str::to_owned).collect()
                },
            )
            .expect("D2 target is canonical"),
        ),
        target: if create {
            TargetState::Absent
        } else {
            TargetState::Existing
        },
        object: if matches!(
            binding.tool_name.as_str(),
            "workspace.files.list" | "workspace.files.search" | "workspace.command.run"
        ) {
            ObjectKind::Other
        } else {
            ObjectKind::RegularFile
        },
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

pub(super) fn command_helper_digest(
    native: &runne_platform::local_command_linux::LinuxCompositeScopeAdmission,
    tool: &str,
) -> Result<Option<IntegrityDigest>, ()> {
    if tool == "workspace.command.run" {
        native
            .tool_helper_executable_digest()
            .map(Some)
            .map_err(|_| ())
    } else {
        Ok(None)
    }
}
