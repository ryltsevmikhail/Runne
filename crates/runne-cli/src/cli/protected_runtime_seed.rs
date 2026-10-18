use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use runne_api::PermissionEffectiveStateV1;
use runne_platform_desktop::{
    DevelopmentBundledRuntimeLauncher, ProtectedBundledRuntimeLaunchSpec,
    ProtectedBundledRuntimeSupervisor, VerifiedRootHandle, discover_bundled_runtime,
    require_linux_cli_baseline_root,
};
use runne_runtime_client::{
    BindWorkspaceRootRequest, CanonicalId, CommandIdentity, CreateProjectRequest,
    CreateWorkspaceRequest, ExistingWorkspaceRequest, ProjectTrustControlRequestDto,
    ProjectTrustDecisionDto, ProtectedRootAdmission,
};

#[path = "protected_runtime_seed_paths.rs"]
mod paths;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const SEED_COMMAND: &str = "seed-empty-root-fixture";

struct SeedResult {
    project_id: CanonicalId,
    workspace_id: CanonicalId,
    runtime_root: PathBuf,
    project_root: PathBuf,
    authorization_revision: u64,
    selected_mode: runne_runtime_client::PermissionModeV1,
    effective: PermissionEffectiveStateV1,
}

pub(super) fn is_seed_only_invocation(arguments: &[OsString]) -> bool {
    let Ok(state) = super::super::parse_global_options(arguments.to_vec()) else {
        return false;
    };
    state.arguments.len() >= 4
        && state.arguments[0] == "permissions"
        && state.arguments[1] == "--protected-runtime-root"
        && state.arguments[3] == SEED_COMMAND
}

pub(super) fn run(arguments: Vec<OsString>) -> super::super::ProcessOutcome {
    let (runtime_root, project_root, format) = match parse_invocation(arguments) {
        Ok(invocation) => invocation,
        Err(error) => {
            return super::super::process_outcome(Err(error), super::super::OutputFormat::Text);
        }
    };
    let seeded = seed(&runtime_root, &project_root)
        .and_then(|seed| effective_state_json(&seed.effective).map(|effective| (seed, effective)));
    match seeded {
        Ok((seed, effective)) => super::super::process_outcome(
            Ok(super::super::CommandOutput::typed(
                format!(
                    "seeded project={} workspace={} authorization_revision={}",
                    seed.project_id, seed.workspace_id, seed.authorization_revision
                ),
                serde_json::json!({
                    "projectId": seed.project_id.to_string(),
                    "workspaceId": seed.workspace_id.to_string(),
                    "runtimeRoot": seed.runtime_root,
                    "projectRoot": seed.project_root,
                    "authorizationRevision": seed.authorization_revision,
                    "selectedMode": seed.selected_mode,
                    "effectiveState": effective,
                }),
            )),
            format,
        ),
        Err(error) => super::super::process_outcome(Err(error), format),
    }
}

/// Encodes the observed effective state as-is (`ready` or `notReady` + reason).
fn effective_state_json(
    effective: &PermissionEffectiveStateV1,
) -> Result<serde_json::Value, super::super::CliError> {
    serde_json::to_value(effective).map_err(|_| super::super::CliError::Runtime)
}

fn parse_invocation(
    arguments: Vec<OsString>,
) -> Result<(PathBuf, PathBuf, super::super::OutputFormat), super::super::CliError> {
    let state = super::super::parse_global_options(arguments)?;
    let format = state.format;
    let mut arguments = state.arguments.into_iter();
    if arguments.next().as_deref() != Some(OsStr::new("permissions"))
        || arguments.next().as_deref() != Some(OsStr::new("--protected-runtime-root"))
    {
        return Err(super::super::CliError::Usage);
    }
    let runtime_root = PathBuf::from(arguments.next().ok_or(super::super::CliError::Usage)?);
    if arguments.next().as_deref() != Some(OsStr::new(SEED_COMMAND))
        || arguments.next().as_deref() != Some(OsStr::new("--project-root"))
    {
        return Err(super::super::CliError::Usage);
    }
    let project_root = PathBuf::from(arguments.next().ok_or(super::super::CliError::Usage)?);
    if arguments.next().is_some() || !runtime_root.is_absolute() || !project_root.is_absolute() {
        return Err(super::super::CliError::Usage);
    }
    Ok((runtime_root, project_root, format))
}

fn seed(runtime_root: &Path, project_root: &Path) -> Result<SeedResult, super::super::CliError> {
    paths::validate(runtime_root, project_root)?;
    require_linux_cli_baseline_root(runtime_root).map_err(|_| super::super::CliError::Runtime)?;
    paths::create_private_empty_runtime_root(runtime_root)?;
    paths::create_private_empty_project_root(project_root)?;
    let executable = std::env::current_exe().map_err(|_| super::super::CliError::Runtime)?;
    let daemon =
        discover_bundled_runtime(&executable).map_err(|_| super::super::CliError::Runtime)?;
    let spec = ProtectedBundledRuntimeLaunchSpec::new(&daemon, runtime_root)
        .map_err(|_| super::super::CliError::Runtime)?;
    require_linux_cli_baseline_root(runtime_root).map_err(|_| super::super::CliError::Runtime)?;
    if !paths::is_empty_directory(runtime_root)? {
        return Err(super::super::CliError::Runtime);
    }
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    let seeded = supervisor
        .start()
        .map_err(|_| super::super::CliError::Runtime)
        .and_then(|()| seed_started(&mut supervisor, runtime_root, project_root));
    let stopped = supervisor
        .stop()
        .map(|_| ())
        .map_err(|_| super::super::CliError::Runtime);
    match (seeded, stopped) {
        (Ok(seed), Ok(())) => Ok(seed),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one seed-only runtime-client sequence owns the fixture lifecycle"
)]
fn seed_started(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    runtime_root: &Path,
    project_root: &Path,
) -> Result<SeedResult, super::super::CliError> {
    let runtime = tokio::runtime::Runtime::new().map_err(|_| super::super::CliError::Runtime)?;
    runtime.block_on(async {
        let profile = supervisor
            .take_runtime_profile()
            .ok_or(super::super::CliError::Runtime)?;
        let client = profile
            .connect(REQUEST_TIMEOUT)
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        supervisor
            .record_client_ready(&client)
            .map_err(|_| super::super::CliError::Runtime)?;
        let project_id = CanonicalId::now_v7();
        let project_command = CanonicalId::now_v7();
        client
            .create_project(
                CreateProjectRequest::new(
                    CommandIdentity::new(
                        project_command,
                        format!("fixture-project-{project_command}"),
                    )
                    .map_err(|_| super::super::CliError::Runtime)?,
                    project_id,
                    "private native warning fixture",
                )
                .map_err(|_| super::super::CliError::Runtime)?,
            )
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        let workspace_id = CanonicalId::now_v7();
        let workspace_command = CanonicalId::now_v7();
        client
            .create_workspace(
                CreateWorkspaceRequest::new(
                    CommandIdentity::new(
                        workspace_command,
                        format!("fixture-workspace-{workspace_command}"),
                    )
                    .map_err(|_| super::super::CliError::Runtime)?,
                    project_id,
                    workspace_id,
                    "private native warning workspace",
                )
                .map_err(|_| super::super::CliError::Runtime)?,
            )
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        let workspace = client
            .get_workspace(workspace_id)
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        if workspace.is_open() {
            return Err(super::super::CliError::Runtime);
        }
        let open_command = CanonicalId::now_v7();
        client
            .open_workspace(
                ExistingWorkspaceRequest::new(
                    CommandIdentity::new(open_command, format!("fixture-open-{open_command}"))
                        .map_err(|_| super::super::CliError::Runtime)?,
                    workspace_id,
                    workspace.version(),
                )
                .map_err(|_| super::super::CliError::Runtime)?,
            )
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        let workspace = client
            .get_workspace(workspace_id)
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        if !workspace.is_open() {
            return Err(super::super::CliError::Runtime);
        }
        let mode_before = client
            .permission_mode_status(workspace_id)
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        let workspace_bytes = hex::decode(workspace_id.to_string().replace('-', ""))
            .map_err(|_| super::super::CliError::Runtime)?;
        let workspace_api_id = runne_api::WorkspaceId::from_bytes(
            workspace_bytes
                .try_into()
                .map_err(|_| super::super::CliError::Runtime)?,
        );
        let verified_root =
            VerifiedRootHandle::open(project_root).map_err(|_| super::super::CliError::Runtime)?;
        let admission = supervisor
            .prepare_root_admission(&verified_root, workspace_api_id, workspace.version())
            .map_err(|_| super::super::CliError::Runtime)?;
        let admission = ProtectedRootAdmission::from_verified(admission)
            .map_err(|_| super::super::CliError::Runtime)?;
        let bind_command = CanonicalId::now_v7();
        client
            .bind_workspace_root(
                BindWorkspaceRootRequest::new(
                    CommandIdentity::new(bind_command, format!("fixture-bind-{bind_command}"))
                        .map_err(|_| super::super::CliError::Runtime)?,
                    workspace_id,
                    workspace.version(),
                    &admission,
                )
                .map_err(|_| super::super::CliError::Runtime)?,
            )
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        let trust = client
            .get_project_trust(project_id, workspace_id)
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        if trust.root_admission_version().is_none() {
            return Err(super::super::CliError::Runtime);
        }
        let confirmed = client
            .decide_project_trust(ProjectTrustControlRequestDto {
                project_id,
                workspace_id,
                decision: ProjectTrustDecisionDto::ConfirmProject,
                expected_epoch: trust.epoch(),
                expected_revision: trust.revision(),
                expected_project_version: trust.project_version(),
                expected_workspace_version: trust.workspace_version(),
                expected_root_admission_version: trust.root_admission_version(),
            })
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        if confirmed.status() != runne_runtime_client::ProjectTrustStatusDto::Trusted {
            return Err(super::super::CliError::Runtime);
        }
        if !paths::is_empty_directory(project_root)? {
            return Err(super::super::CliError::Runtime);
        }
        let mode_after = client
            .permission_mode_status(workspace_id)
            .await
            .map_err(|_| super::super::CliError::Runtime)?;
        if mode_before.selected_mode != mode_after.selected_mode
            || mode_before.authorization_revision != mode_after.authorization_revision
        {
            return Err(super::super::CliError::Runtime);
        }
        Ok(SeedResult {
            project_id,
            workspace_id,
            runtime_root: runtime_root.to_path_buf(),
            project_root: project_root.to_path_buf(),
            authorization_revision: mode_after.authorization_revision,
            selected_mode: mode_after.selected_mode,
            effective: mode_after.effective,
        })
    })
}

#[cfg(test)]
#[path = "protected_runtime_seed_tests.rs"]
mod tests;
