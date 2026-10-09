#[cfg(not(test))]
#[expect(
    clippy::wildcard_imports,
    reason = "owner composes tightly scoped CLI sibling APIs"
)]
use super::*;
#[cfg(test)]
use super::*;
use runne_api::PermissionModeNativePendingV2;
use runne_platform_desktop::permission_reauth_linux::{
    NativePermissionWarningMainThreadScheduler, PamConversationHandler,
};
use runne_platform_desktop::{
    DevelopmentBundledRuntimeLauncher, ProtectedBundledRuntimeLaunchSpec,
    ProtectedBundledRuntimeSupervisor, discover_bundled_runtime, require_linux_cli_baseline_root,
};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[path = "protected_runtime_ensure.rs"]
mod protected_runtime_ensure;

macro_rules! lifecycle_test_barrier {
    ($name:literal) => {
        #[cfg(test)]
        super::protected_runtime_tests::barrier($name);
    };
}
pub fn run(
    arguments: Vec<OsString>,
    scheduler: Arc<dyn NativePermissionWarningMainThreadScheduler>,
    pam: Arc<dyn PamConversationHandler>,
) -> ProcessOutcome {
    let (result, format) = match parse_global_options(arguments) {
        Ok(state) => {
            let format = state.format;
            let result = match parse_invocation(state) {
                Ok((root, command)) => tokio::runtime::Runtime::new()
                    .map_or(Err(CliError::Runtime), |runtime| {
                        runtime.block_on(run_owned(root, command, scheduler, pam))
                    }),
                Err(error) => Err(error),
            };
            (result, format)
        }
        Err(error) => (Err(error), OutputFormat::Text),
    };
    process_outcome(result, format)
}
pub fn parse_invocation(state: CliState) -> Result<(PathBuf, ProtectedCommand), CliError> {
    let mut arguments = VecDeque::from(state.arguments);
    let profile = if peek(&arguments) == Some("--profile") {
        let _ = arguments.pop_front();
        Some(PathBuf::from(arguments.pop_front().ok_or(CliError::Usage)?))
    } else {
        None
    };
    let command = pop_string(&mut arguments)?;
    if command != "permissions" || profile.is_some() {
        return Err(CliError::Usage);
    }
    expect_token(&mut arguments, "--protected-runtime-root")?;
    let root = PathBuf::from(arguments.pop_front().ok_or(CliError::Usage)?);
    if !root.is_absolute() {
        return Err(CliError::Usage);
    }
    let project_root = if peek(&arguments) == Some("--project-root") {
        let _ = arguments.pop_front();
        let project_root = PathBuf::from(arguments.pop_front().ok_or(CliError::Usage)?);
        if !project_root.is_absolute() {
            return Err(CliError::Usage);
        }
        Some(project_root)
    } else {
        None
    };
    let command = parse_permissions(arguments)?;
    Ok((
        root,
        ProtectedCommand {
            command,
            project_root,
        },
    ))
}
pub struct ProtectedCommand {
    pub command: ParsedPermissionsCommand,
    pub project_root: Option<PathBuf>,
}
#[expect(clippy::future_not_send, reason = "future is polled by the GTK thread")]
async fn run_owned(
    root: PathBuf,
    command: ProtectedCommand,
    scheduler: Arc<dyn NativePermissionWarningMainThreadScheduler>,
    pam: Arc<dyn PamConversationHandler>,
) -> Result<CommandOutput, CliError> {
    require_linux_cli_baseline_root(&root).map_err(|_| CliError::Runtime)?;
    let executable = std::env::current_exe().map_err(|_| CliError::Runtime)?;
    let daemon = discover_bundled_runtime(&executable).map_err(|_| CliError::Runtime)?;
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(&daemon, &root).map_err(|_| CliError::Runtime)?;
    lifecycle_test_barrier!("before_start");
    let supervisor = Mutex::new(ProtectedBundledRuntimeSupervisor::new(
        DevelopmentBundledRuntimeLauncher::new(),
        spec,
    ));
    let result = async {
        let profile = {
            let mut owner = supervisor.lock().map_err(|_| CliError::Runtime)?;
            owner.start().map_err(|_| CliError::Runtime)?;
            if owner
                .pending_profile_is_v3()
                .map_err(|_| CliError::Runtime)?
            {
                return Err(CliError::Runtime);
            }
            owner.take_runtime_profile().ok_or(CliError::Runtime)?
        };
        let client = profile
            .connect(REQUEST_TIMEOUT)
            .await
            .map_err(|_| CliError::Runtime)?;
        {
            let mut owner = supervisor.lock().map_err(|_| CliError::Runtime)?;
            owner
                .record_client_ready(&client)
                .map_err(|_| CliError::Runtime)?;
        }
        require_linux_cli_baseline_root(&root).map_err(|_| CliError::Runtime)?;
        if let Some(project_root) = &command.project_root {
            // Re-bind of an existing binding: the workspace must already be open
            // and already trusted; only the admission nonce and the bound root
            // version move forward. This path grants no trust and opens no
            // workspace.
            let workspace_id = match &command.command {
                ParsedPermissionsCommand::Read(
                    PermissionsCommand::Status { workspace_id }
                    | PermissionsCommand::CommandStatus { workspace_id, .. },
                ) => *workspace_id,
                ParsedPermissionsCommand::ModeSet(intent) => intent.workspace_id,
                ParsedPermissionsCommand::Read(PermissionsCommand::ApprovalsList)
                | ParsedPermissionsCommand::ApprovalRespond(_) => {
                    return Err(CliError::Usage);
                }
            };
            protected_runtime_ensure::ensure_workspace_root_bound(
                &client,
                &supervisor,
                &root,
                project_root,
                workspace_id,
            )
            .await?;
        }
        let runtime = ProtectedPermissionsRuntime {
            client: &client,
            supervisor: &supervisor,
            scheduler,
            pam,
        };
        match command.command {
            ParsedPermissionsCommand::Read(read) => execute_permissions(&runtime, read).await,
            ParsedPermissionsCommand::ModeSet(intent) => {
                #[cfg(target_os = "linux")]
                {
                    let state = dirs::state_dir()
                        .ok_or(CliError::PermissionRecoveryIo(intent.command_id))?;
                    let index = LinuxPermissionRecoveryIndex::new(state);
                    execute_mode_set_with_index(&runtime, intent, &index).await
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = intent;
                    Err(CliError::Runtime)
                }
            }
            ParsedPermissionsCommand::ApprovalRespond(intent) => {
                execute_approval_response(&client, intent).await
            }
        }
    }
    .await;
    let stopped = supervisor.lock().map_err(|_| CliError::Runtime)?.stop();
    let stopped = stopped.map(|_| ()).map_err(|_| CliError::Runtime);
    match (result, stopped) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}
pub struct ProtectedPermissionsRuntime<'a> {
    pub(super) client: &'a AuthenticatedRuntimeClient,
    pub(super) supervisor: &'a Mutex<ProtectedBundledRuntimeSupervisor>,
    pub(super) scheduler: Arc<dyn NativePermissionWarningMainThreadScheduler>,
    pub(super) pam: Arc<dyn PamConversationHandler>,
}
include!("protected_runtime_owner_runtime.rs");
