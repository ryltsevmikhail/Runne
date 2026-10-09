use runne_domain::id::IntegrityDigest;
use sha2::{Digest, Sha256};

use super::{
    composite::{ChildDelegationScope, FilesystemPosture, ManagedPolicyCoverage, NetworkScope},
    local_command_binding::{
        CLOSED_RULES_ENCODER_VERSION_V2, LOCAL_COMMAND_PERMISSION_BINDING_COMPILER_VERSION,
        LOCAL_COMMAND_PERMISSION_BINDING_SCHEMA_VERSION, LocalCommandPermissionBindingInputV1,
        LocalCommandPermissionBindingV1,
    },
    local_command_limits::LocalInvocationLimitsV1,
    local_command_validation::LocalCommandPermissionBindingError,
    model::PermissionMode,
};

pub(super) fn local_command_permission_binding_digest(
    binding: &LocalCommandPermissionBindingV1,
) -> IntegrityDigest {
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:local-command-permission-binding:v1\0");
    hash.update(LOCAL_COMMAND_PERMISSION_BINDING_SCHEMA_VERSION.to_be_bytes());
    hash.update(LOCAL_COMMAND_PERMISSION_BINDING_COMPILER_VERSION.to_be_bytes());
    hash.update(CLOSED_RULES_ENCODER_VERSION_V2.to_be_bytes());
    hash.update(crate::project_trust::FROZEN_POLICY_VERSION.to_be_bytes());
    hash.update(crate::project_trust::LOCAL_COMMAND_POLICY_VERSION.to_be_bytes());

    let selection_scope = &binding.selection.scope;
    put_bytes(&mut hash, selection_scope.runtime_authority_id.0.as_bytes());
    put_bytes(&mut hash, selection_scope.principal_id.as_str().as_bytes());
    hash.update(selection_scope.workspace_id.as_bytes());
    hash.update([mode_tag(binding.selection.selected_mode)]);
    hash.update(binding.selection.preset_version.as_u16().to_be_bytes());
    hash.update(binding.selection.authorization_revision.to_be_bytes());
    put_option_i64(&mut hash, binding.selection.expires_at_unix_ms);

    hash.update(binding.assignment.taskrun_id.as_bytes());
    hash.update(binding.assignment.attempt_id.as_bytes());
    put_bytes(&mut hash, binding.assignment.node_id.0.as_bytes());
    hash.update(binding.assignment.node_epoch.to_be_bytes());
    hash.update(binding.assignment.fence.0.to_be_bytes());
    hash.update(binding.claim_stream_version.to_be_bytes());
    hash.update(binding.invocation_id.as_bytes());

    hash.update(binding.project_id.as_bytes());
    hash.update(binding.project_version.to_be_bytes());
    hash.update(binding.workspace_version.to_be_bytes());
    hash.update(binding.admitted_root_version.to_be_bytes());
    hash.update(binding.held_root_identity_digest.as_bytes());
    hash.update(binding.command_intent_digest.as_bytes());
    hash.update(binding.approval.digest().as_bytes());
    hash.update(binding.scope_digest.as_bytes());
    hash.update(binding.closed_rules_digest.as_bytes());
    hash.update(local_invocation_limits_digest(binding.limits).as_bytes());
    IntegrityDigest::from_bytes(hash.finalize().into())
}

pub(super) fn local_invocation_limits_digest(limits: LocalInvocationLimitsV1) -> IntegrityDigest {
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:local-invocation-limits:v1\0");
    hash.update(1_u16.to_be_bytes());
    hash.update([limits.admitted_invocations()]);
    hash.update(limits.stdout_capture_bytes().to_be_bytes());
    hash.update(limits.stderr_capture_bytes().to_be_bytes());
    hash.update(limits.max_runtime_ms().to_be_bytes());
    IntegrityDigest::from_bytes(hash.finalize().into())
}

fn mode_tag(mode: PermissionMode) -> u8 {
    match mode {
        PermissionMode::AskAlways => 1,
        PermissionMode::RiskBased => 2,
        PermissionMode::FullAccess => 3,
    }
}

fn put_bytes(hash: &mut Sha256, value: &[u8]) {
    // Construction enforces a total payload below 1 MiB, so this cast is exact.
    hash.update((value.len() as u32).to_be_bytes());
    hash.update(value);
}

fn put_option_i64(hash: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash.update(value.to_be_bytes());
        }
        None => hash.update([0]),
    }
}

pub(super) fn validate_binding_size(
    input: &LocalCommandPermissionBindingInputV1,
) -> Result<(), LocalCommandPermissionBindingError> {
    let mut size = SizeCounter::default();
    size.add(2 + 2 + 2 + 4 + 4)?;
    size.text(&input.selection.scope.runtime_authority_id.0)?;
    size.text(input.selection.scope.principal_id.as_str())?;
    size.add(input.selection.scope.workspace_id.as_bytes().len() + 1 + 2 + 8 + 1)?;
    if input.selection.expires_at_unix_ms.is_some() {
        size.add(8)?;
    }

    size.add(
        input.assignment.taskrun_id.as_bytes().len() + input.assignment.attempt_id.as_bytes().len(),
    )?;
    size.text(&input.assignment.node_id.0)?;
    size.add(8 + 8 + 8 + input.invocation_id.as_bytes().len())?;
    size.add(
        input.project_id.as_bytes().len()
            + 8
            + 8
            + 8
            + input.held_root_identity_digest.as_bytes().len(),
    )?;

    size.add(1)?;
    size.text(input.command.executable().value())?;
    size.text(input.command.cwd())?;
    size.add(4)?;
    for argument in input.command.argv() {
        size.text(argument)?;
    }
    size.add(4)?;
    for (key, value) in input.command.env() {
        size.text(key)?;
        size.text(value)?;
    }
    size.add(input.command_intent_digest.as_bytes().len())?;

    let approval = &input.approval;
    size.add(1 + 32 + 32)?;
    size.text(approval.principal_id.as_str())?;
    size.add(
        approval.invocation.task_run_id.as_bytes().len()
            + approval.invocation.attempt_id.as_bytes().len()
            + approval.invocation.invocation_id.as_bytes().len()
            + 32
            + 8
            + 32
            + 32
            + 1,
    )?;
    if approval.executable_digest.is_some() {
        size.add(32)?;
    }
    size.add(32 + 1 + 32 + 8)?;

    size.text(&input.scope.permission_scope.runtime_authority_id.0)?;
    size.text(input.scope.permission_scope.principal_id.as_str())?;
    size.add(input.scope.permission_scope.workspace_id.as_bytes().len() + 32 + 1)?;
    match &input.scope.filesystem.posture {
        FilesystemPosture::None | FilesystemPosture::BroadSameUser => size.add(1)?,
        FilesystemPosture::BoundedRoots(roots) => {
            size.add(1 + 4)?;
            for root in roots {
                size.add(root.root_identity.as_bytes().len() + 4)?;
                for component in &root.components {
                    size.text(component)?;
                }
            }
        }
    }
    size.add(4 + input.scope.filesystem.permissions.len())?;
    match input.scope.network {
        NetworkScope::None | NetworkScope::BroadSameUser => size.add(1)?,
        NetworkScope::Brokered { .. } => size.add(1 + 32)?,
    }
    match input.scope.children {
        ChildDelegationScope::None | ChildDelegationScope::Unbounded => size.add(1)?,
        ChildDelegationScope::MaxDepth(_) => size.add(1 + 2)?,
    }
    size.add(1 + usize::from(input.scope.budget.max_operations.is_some()) * 8)?;
    size.add(1 + usize::from(input.scope.budget.max_bytes.is_some()) * 8 + 8)?;
    match input.scope.managed_policy {
        ManagedPolicyCoverage::Closed(_) => size.add(1 + 16 + snapshot_size() + 32)?,
        ManagedPolicyCoverage::Unrestricted { .. } | ManagedPolicyCoverage::Restricted { .. } => {
            size.add(1 + 32)?;
        }
    }
    size.add(1 + 32)?;

    size.add(snapshot_size() + input.closed_rules_digest.as_bytes().len())?;
    size.add(2 + 1 + 8 + 8 + 8)?;
    Ok(())
}

#[derive(Default)]
struct SizeCounter(usize);

impl SizeCounter {
    fn add(&mut self, amount: usize) -> Result<(), LocalCommandPermissionBindingError> {
        self.0 = self
            .0
            .checked_add(amount)
            .ok_or(LocalCommandPermissionBindingError::BindingTooLarge)?;
        if self.0 > 1024 * 1024 {
            return Err(LocalCommandPermissionBindingError::BindingTooLarge);
        }
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), LocalCommandPermissionBindingError> {
        let length = u32::try_from(value.len())
            .map_err(|_| LocalCommandPermissionBindingError::BindingTooLarge)?;
        self.add(4)?;
        self.add(length as usize)
    }
}

fn snapshot_size() -> usize {
    1 + 4 + 8 + 8 + 4 + 12
}
