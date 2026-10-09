use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path};
use std::sync::Mutex;

use runne_platform_desktop::{ProtectedBundledRuntimeSupervisor, VerifiedRootHandle};
use runne_runtime_client::{
    BindWorkspaceRootRequest, CanonicalId, CommandIdentity, ProjectTrustStatusDto,
    ProtectedRootAdmission,
};

/// Re-binds the workspace root of an already open, already trusted workspace.
///
/// This is a re-bind of an existing binding: `bind_workspace_root` consumes a
/// fresh admission nonce and moves the bound root version forward so the
/// current daemon process can observe the root. It never grants project trust
/// (no `decide_project_trust`) and never opens a workspace (no
/// `open_workspace`); a closed or untrusted workspace fails closed.
///
/// Trust is checked BEFORE bind: bind is not performed for an untrusted
/// workspace, so an untrusted workspace never reaches
/// `prepare_root_admission`/`bind_workspace_root` and consumes no nonce.
/// The pre-bind gate requires only trust: the root admission version appears
/// only after `bind_workspace_root` records it (a fresh daemon process has no
/// in-memory active binding yet). It is required by the post-bind re-read.
pub(super) async fn ensure_workspace_root_bound(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    supervisor: &Mutex<ProtectedBundledRuntimeSupervisor>,
    runtime_root: &Path,
    project_root: &Path,
    workspace_id: CanonicalId,
) -> Result<(), super::super::CliError> {
    let workspace = client
        .get_workspace(workspace_id)
        .await
        .map_err(|_| super::super::CliError::Runtime)?;
    if !workspace.is_open() {
        return Err(super::super::CliError::Runtime);
    }
    validate_rebind_root(runtime_root, project_root)?;
    let project_id = workspace.project_id();
    let workspace_bytes = hex::decode(workspace_id.to_string().replace('-', ""))
        .map_err(|_| super::super::CliError::Runtime)?;
    let workspace_api_id = runne_api::WorkspaceId::from_bytes(
        workspace_bytes
            .try_into()
            .map_err(|_| super::super::CliError::Runtime)?,
    );
    // Pre-bind trust gate: trust is checked before bind; bind is not
    // performed for an untrusted workspace, so this read-only check must pass
    // before any admission nonce is prepared or consumed. The admission
    // version is not required here: this gate precedes any mutation, and the
    // version is only created by the bind below.
    require_trusted_root_admission(client, project_id, workspace_id, false).await?;
    let verified_root =
        VerifiedRootHandle::open(project_root).map_err(|_| super::super::CliError::Runtime)?;
    let admission = supervisor
        .lock()
        .map_err(|_| super::super::CliError::Runtime)?
        .prepare_root_admission(&verified_root, workspace_api_id, workspace.version())
        .map_err(|_| super::super::CliError::Runtime)?;
    let admission = ProtectedRootAdmission::from_verified(admission)
        .map_err(|_| super::super::CliError::Runtime)?;
    let bind_command = CanonicalId::now_v7();
    client
        .bind_workspace_root(
            BindWorkspaceRootRequest::new(
                CommandIdentity::new(bind_command, format!("ensure-bind-{bind_command}"))
                    .map_err(|_| super::super::CliError::Runtime)?,
                workspace_id,
                workspace.version(),
                &admission,
            )
            .map_err(|_| super::super::CliError::Runtime)?,
        )
        .await
        .map_err(|_| super::super::CliError::Runtime)?;
    // Post-bind re-read: the freshly bound workspace must still be trusted
    // and must now carry a recorded root admission version (created by the
    // bind above); anything else fails closed.
    require_trusted_root_admission(client, project_id, workspace_id, true).await?;
    Ok(())
}

/// Read-only trust gate shared by the pre-bind and post-bind checks.
///
/// Always requires the workspace to be trusted. `require_admission_version`
/// additionally requires a recorded root admission version: that version is
/// recorded only by `bind_workspace_root`, so the pre-bind gate runs without
/// it (an in-memory admission-less fresh daemon would otherwise fail closed
/// before bind could create the version), while the post-bind re-read demands
/// it. `get_project_trust` mutates nothing, so either call leaves no nonce or
/// root-version changes behind when it fails.
async fn require_trusted_root_admission(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    project_id: CanonicalId,
    workspace_id: CanonicalId,
    require_admission_version: bool,
) -> Result<(), super::super::CliError> {
    let trust = client
        .get_project_trust(project_id, workspace_id)
        .await
        .map_err(|_| super::super::CliError::Runtime)?;
    if trust.status() != ProjectTrustStatusDto::Trusted {
        return Err(super::super::CliError::Runtime);
    }
    if require_admission_version && trust.root_admission_version().is_none() {
        return Err(super::super::CliError::Runtime);
    }
    Ok(())
}

/// Fail-closed `--project-root` shape check for the re-bind path.
///
/// Argument-shaped violations (non-absolute path, `..` or `.` components,
/// missing or non-directory target) report [`CliError::Usage`]; confinement
/// violations (the target and the protected runtime root resolving inside one
/// another) and ownership violations (foreign owner, group/other-writable
/// directory, parent that is not 0700-compatible) fail closed as
/// [`CliError::Runtime`].
fn validate_rebind_root(
    runtime_root: &Path,
    project_root: &Path,
) -> Result<(), super::super::CliError> {
    if !project_root.is_absolute()
        || project_root
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || has_dot_segment(project_root)
    {
        return Err(super::super::CliError::Usage);
    }
    let metadata = fs::metadata(project_root).map_err(|_| super::super::CliError::Usage)?;
    if !metadata.is_dir() {
        return Err(super::super::CliError::Usage);
    }
    let canonical_runtime_root =
        fs::canonicalize(runtime_root).map_err(|_| super::super::CliError::Runtime)?;
    let canonical_project_root =
        fs::canonicalize(project_root).map_err(|_| super::super::CliError::Runtime)?;
    if canonical_project_root.starts_with(&canonical_runtime_root)
        || canonical_runtime_root.starts_with(&canonical_project_root)
    {
        return Err(super::super::CliError::Runtime);
    }
    require_owner_mode(&metadata, 0o022)?;
    let parent = canonical_project_root
        .parent()
        .ok_or(super::super::CliError::Runtime)?;
    let parent_metadata = fs::metadata(parent).map_err(|_| super::super::CliError::Runtime)?;
    if !parent_metadata.is_dir() {
        return Err(super::super::CliError::Runtime);
    }
    require_owner_mode(&parent_metadata, 0o077)
}

/// Detects a literal `.` path segment in the raw argument.
///
/// `Path::components` normalizes `.` segments away (except a leading `./`),
/// so a trailing `/.` or an embedded `/./` never yields a `Component::CurDir`;
/// both are still argument-shaped dot segments and must report `Usage`.
fn has_dot_segment(path: &Path) -> bool {
    path.as_os_str()
        .as_encoded_bytes()
        .split(|byte| *byte == b'/')
        .any(|segment| segment == b".")
}

/// Requires `metadata` to name a directory tree node owned by the current
/// effective user with none of `forbidden_bits` set in its mode.
fn require_owner_mode(
    metadata: &fs::Metadata,
    forbidden_bits: u32,
) -> Result<(), super::super::CliError> {
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & forbidden_bits != 0
    {
        return Err(super::super::CliError::Runtime);
    }
    Ok(())
}

#[cfg(test)]
#[path = "protected_runtime_ensure_tests.rs"]
mod tests;
