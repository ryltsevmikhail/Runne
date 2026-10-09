use runne_domain::{
    id::IntegrityDigest,
    task_run::{
        MAX_LOCAL_COMMAND_ARGV, MAX_LOCAL_COMMAND_BYTES, MAX_LOCAL_COMMAND_ENV, TaskRunExecutable,
    },
};

use super::{
    composite::{CompositeScopeDigest, FilesystemPosture, ManagedPolicyCoverage},
    local_command_binding::LocalCommandPermissionBindingInputV1,
    local_command_limits::MAX_LOCAL_COMMAND_CAPTURE_BYTES,
    model::PresetVersion,
};

use crate::project_trust::{ProjectTrustProjectId, managed_effect_policy_digest_v2};

/// Failure to check a portable X2 command binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCommandPermissionBindingError {
    /// A version or positive identity field is unsupported.
    UnsupportedVersionOrIdentity,
    /// The exact command exceeds an existing or native boundary.
    InvalidCommand,
    /// A workspace root or composite scope is malformed or too large.
    InvalidScope,
    /// Duplicated task, attempt, invocation, principal, or scope fields disagree.
    IdentityMismatch,
    /// The complete managed snapshot is invalid or disagrees with its scope.
    InvalidManagedSnapshot,
    /// A supplied command, policy, or scope digest is not canonical.
    DigestMismatch,
    /// The complete source binding exceeds the one-mebibyte cap.
    BindingTooLarge,
    /// The invocation output or runtime limits are invalid.
    InvalidLimits,
}

/// Validates data shape and returns the canonical composite digest.
pub(super) fn validate_local_command_permission_binding(
    input: &LocalCommandPermissionBindingInputV1,
) -> Result<CompositeScopeDigest, LocalCommandPermissionBindingError> {
    validate_command(input)?;
    validate_root_bounds(input)?;
    super::local_command_digest::validate_binding_size(input)?;

    if input.selection.preset_version != PresetVersion::V1
        || input.project_version == 0
        || input.workspace_version == 0
        || input.admitted_root_version == 0
        || input.claim_stream_version == 0
        || input.assignment.node_epoch == 0
        || input.assignment.fence.0 == 0
        || input
            .held_root_identity_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || input
            .selection
            .expires_at_unix_ms
            .is_some_and(|expiry| expiry <= 0)
        || input.approval.expires_at_unix_ms <= 0
    {
        return Err(LocalCommandPermissionBindingError::UnsupportedVersionOrIdentity);
    }
    if input.limits.admitted_invocations() != 1
        || input.limits.stdout_capture_bytes() > MAX_LOCAL_COMMAND_CAPTURE_BYTES as u64
        || input.limits.stderr_capture_bytes() > MAX_LOCAL_COMMAND_CAPTURE_BYTES as u64
        || input.limits.max_runtime_ms() == 0
        || input.limits.stdout_capture_bytes_usize().is_err()
        || input.limits.stderr_capture_bytes_usize().is_err()
        || input.limits.max_runtime().is_err()
    {
        return Err(LocalCommandPermissionBindingError::InvalidLimits);
    }
    if input.selection.scope != input.scope.permission_scope
        || input.assignment.taskrun_id != input.approval.invocation.task_run_id
        || input.assignment.attempt_id != input.approval.invocation.attempt_id
        || input.invocation_id != input.approval.invocation.invocation_id
        || input.selection.scope.principal_id != input.approval.principal_id
        || input.approval.action != super::resource::PermissionAction::ProcessStart
        || input.approval.executable_digest.is_none()
    {
        return Err(LocalCommandPermissionBindingError::IdentityMismatch);
    }
    input
        .scope
        .validate()
        .map_err(|_| LocalCommandPermissionBindingError::InvalidScope)?;

    let trust_project = ProjectTrustProjectId::from_bytes(*input.project_id.as_bytes());
    if !input.closed_rules_snapshot.is_valid() {
        return Err(LocalCommandPermissionBindingError::InvalidManagedSnapshot);
    }
    let canonical_policy_digest =
        managed_effect_policy_digest_v2(trust_project, &input.closed_rules_snapshot)
            .map(IntegrityDigest::from_bytes)
            .ok_or(LocalCommandPermissionBindingError::InvalidManagedSnapshot)?;
    if canonical_policy_digest != input.closed_rules_digest {
        return Err(LocalCommandPermissionBindingError::DigestMismatch);
    }
    let reconstructed =
        ManagedPolicyCoverage::from_closed_snapshot(trust_project, &input.closed_rules_snapshot)
            .ok_or(LocalCommandPermissionBindingError::InvalidManagedSnapshot)?;
    if reconstructed != input.scope.managed_policy {
        return Err(LocalCommandPermissionBindingError::InvalidManagedSnapshot);
    }

    let scope_digest = input
        .scope
        .digest()
        .map_err(|_| LocalCommandPermissionBindingError::InvalidScope)?;
    if input.approval.composite_scope_digest != scope_digest
        || input.approval.containment_version != input.scope.containment
    {
        return Err(LocalCommandPermissionBindingError::DigestMismatch);
    }
    let command_digest = IntegrityDigest::from_bytes(input.command.intent_digest());
    if command_digest != input.command_intent_digest {
        return Err(LocalCommandPermissionBindingError::DigestMismatch);
    }
    Ok(scope_digest)
}

fn validate_command(
    input: &LocalCommandPermissionBindingInputV1,
) -> Result<(), LocalCommandPermissionBindingError> {
    let command = &input.command;
    if command.argv().is_empty()
        || command.argv().len() > MAX_LOCAL_COMMAND_ARGV
        || command.env().len() > MAX_LOCAL_COMMAND_ENV
        || command.cwd().len() > 4096
        || command.executable().value().len() > 4096
        || input.selection.scope.runtime_authority_id.0.is_empty()
        || input.selection.scope.principal_id.as_str().is_empty()
    {
        return Err(LocalCommandPermissionBindingError::InvalidCommand);
    }
    match command.executable() {
        TaskRunExecutable::WorkspaceRelative(path) if !relative_path(path, false) => {
            return Err(LocalCommandPermissionBindingError::InvalidCommand);
        }
        TaskRunExecutable::SystemProgram(id) if !catalog_id(id) => {
            return Err(LocalCommandPermissionBindingError::InvalidCommand);
        }
        _ => {}
    }
    if !relative_path(command.cwd(), true) {
        return Err(LocalCommandPermissionBindingError::InvalidCommand);
    }

    let mut aggregate = command
        .executable()
        .value()
        .len()
        .checked_add(command.cwd().len())
        .ok_or(LocalCommandPermissionBindingError::InvalidCommand)?;
    for argument in command.argv() {
        if argument.len() > 16 * 1024 || argument.as_bytes().contains(&0) {
            return Err(LocalCommandPermissionBindingError::InvalidCommand);
        }
        aggregate = aggregate
            .checked_add(argument.len())
            .ok_or(LocalCommandPermissionBindingError::InvalidCommand)?;
    }
    for (index, (key, value)) in command.env().iter().enumerate() {
        if !env_key(key)
            || value.len() > 16 * 1024
            || value.as_bytes().contains(&0)
            || key
                .len()
                .checked_add(1)
                .and_then(|n| n.checked_add(value.len()))
                .is_none_or(|entry| entry > 16 * 1024)
            || (index > 0 && command.env()[index - 1].0.as_str() >= key.as_str())
        {
            return Err(LocalCommandPermissionBindingError::InvalidCommand);
        }
        aggregate = aggregate
            .checked_add(key.len())
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(LocalCommandPermissionBindingError::InvalidCommand)?;
    }
    if aggregate > MAX_LOCAL_COMMAND_BYTES {
        return Err(LocalCommandPermissionBindingError::InvalidCommand);
    }
    Ok(())
}

fn validate_root_bounds(
    input: &LocalCommandPermissionBindingInputV1,
) -> Result<(), LocalCommandPermissionBindingError> {
    let FilesystemPosture::BoundedRoots(roots) = &input.scope.filesystem.posture else {
        return Ok(());
    };
    if roots.len() > 64 {
        return Err(LocalCommandPermissionBindingError::InvalidScope);
    }
    for root in roots {
        if root.components.len() > 256 {
            return Err(LocalCommandPermissionBindingError::InvalidScope);
        }
        let mut path_bytes = root.components.len().saturating_sub(1);
        for component in &root.components {
            if component.len() > 255 {
                return Err(LocalCommandPermissionBindingError::InvalidScope);
            }
            path_bytes = path_bytes
                .checked_add(component.len())
                .ok_or(LocalCommandPermissionBindingError::InvalidScope)?;
        }
        if path_bytes > 4096 {
            return Err(LocalCommandPermissionBindingError::InvalidScope);
        }
    }
    Ok(())
}

fn relative_path(value: &str, allow_dot: bool) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.as_bytes().contains(&0)
        && (allow_dot && value == "."
            || value
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."))
}

fn catalog_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn env_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= 128
}
