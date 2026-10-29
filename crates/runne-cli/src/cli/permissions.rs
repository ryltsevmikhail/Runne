use std::future::Future;
use std::pin::Pin;

use runne_runtime_client::{
    ApprovalSummaryDto, PermissionModeCommandStatusV2, PermissionModeStatusV1,
};

#[cfg(target_os = "linux")]
#[path = "protected_runtime_owner.rs"]
mod protected_runtime_owner;
#[cfg(all(test, target_os = "linux"))]
#[path = "protected_runtime_project_root_tests.rs"]
mod protected_runtime_project_root_tests;
#[cfg(all(test, target_os = "linux"))]
#[path = "protected_runtime_tests.rs"]
pub(crate) mod protected_runtime_tests;
#[cfg(target_os = "linux")]
#[path = "protected_runtime_ui.rs"]
mod protected_runtime_ui;

enum PermissionsCommand {
    Status {
        workspace_id: CanonicalId,
    },
    CommandStatus {
        workspace_id: CanonicalId,
        command_id: CanonicalId,
    },
    ApprovalsList,
}

type PermissionFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RuntimeApiError>> + Send + 'a>>;

trait PermissionsRuntime {
    fn permission_mode_status(
        &self,
        workspace_id: CanonicalId,
    ) -> PermissionFuture<'_, PermissionModeStatusV1>;

    fn permission_mode_command_status(
        &self,
        workspace_id: CanonicalId,
        command_id: CanonicalId,
    ) -> PermissionFuture<'_, PermissionModeCommandStatusV2>;

    fn list_pending_approvals(&self) -> PermissionFuture<'_, Vec<ApprovalSummaryDto>>;
}

impl PermissionsRuntime for AuthenticatedRuntimeClient {
    fn permission_mode_status(
        &self,
        workspace_id: CanonicalId,
    ) -> PermissionFuture<'_, PermissionModeStatusV1> {
        Box::pin(Self::permission_mode_status(self, workspace_id))
    }

    fn permission_mode_command_status(
        &self,
        workspace_id: CanonicalId,
        command_id: CanonicalId,
    ) -> PermissionFuture<'_, PermissionModeCommandStatusV2> {
        Box::pin(Self::permission_mode_command_status(
            self,
            workspace_id,
            command_id,
        ))
    }

    fn list_pending_approvals(&self) -> PermissionFuture<'_, Vec<ApprovalSummaryDto>> {
        Box::pin(Self::list_pending_approvals(self))
    }
}

#[cfg(target_os = "linux")]
impl PermissionsRuntime for protected_runtime_owner::ProtectedPermissionsRuntime<'_> {
    fn permission_mode_status(
        &self,
        workspace_id: CanonicalId,
    ) -> PermissionFuture<'_, PermissionModeStatusV1> {
        Box::pin(self.client.permission_mode_status(workspace_id))
    }

    fn permission_mode_command_status(
        &self,
        workspace_id: CanonicalId,
        command_id: CanonicalId,
    ) -> PermissionFuture<'_, PermissionModeCommandStatusV2> {
        Box::pin(
            self.client
                .permission_mode_command_status(workspace_id, command_id),
        )
    }

    fn list_pending_approvals(&self) -> PermissionFuture<'_, Vec<ApprovalSummaryDto>> {
        Box::pin(self.client.list_pending_approvals())
    }
}

#[cfg(target_os = "linux")]
fn permission_ceremony_deadline(unix_ms: u64) -> Option<std::time::Instant> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis();
    let now = u64::try_from(now).ok()?;
    std::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(unix_ms.checked_sub(now)?))
}

#[cfg(target_os = "linux")]
const fn permission_selection(
    mode: runne_runtime_client::PermissionModeV1,
) -> runne_api::PermissionModeSelectionV1 {
    match mode {
        runne_runtime_client::PermissionModeV1::AskAlways => {
            runne_api::PermissionModeSelectionV1::AskAlways
        }
        runne_runtime_client::PermissionModeV1::RiskBased => {
            runne_api::PermissionModeSelectionV1::RiskBased
        }
        runne_runtime_client::PermissionModeV1::FullAccess => {
            runne_api::PermissionModeSelectionV1::FullAccess
        }
    }
}

#[cfg(target_os = "linux")]
const fn unavailable_mode_error() -> ModeApiError {
    ModeApiError::UnknownAfterSend
}

type ModeFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ModeApiError>> + Send + 'a>>;

#[derive(Debug)]
enum ModeApiError {
    NotFound,
    UnknownAfterSend,
    Api(RuntimeApiError),
}

impl ModeApiError {
    fn from_runtime(error: RuntimeApiError) -> Self {
        match error.kind() {
            runne_runtime_client::RuntimeApiErrorKind::NotFound => Self::NotFound,
            runne_runtime_client::RuntimeApiErrorKind::UnknownAfterSend => Self::UnknownAfterSend,
            _ => Self::Api(error),
        }
    }
}

trait PermissionModeRuntime: PermissionsRuntime {
    fn session_info(&self) -> &runne_runtime_client::RuntimeSessionInfo;

    fn read_mode_status(&self, workspace_id: CanonicalId)
    -> ModeFuture<'_, PermissionModeStatusV1>;

    fn read_mode_command(
        &self,
        workspace_id: CanonicalId,
        command_id: CanonicalId,
    ) -> ModeFuture<'_, PermissionModeCommandStatusV2>;

    fn request_permission_mode_change(
        &self,
        request: runne_runtime_client::PermissionModeChangeRequestV1,
    ) -> ModeFuture<'_, PermissionModeCommandStatusV2>;
}

impl PermissionModeRuntime for AuthenticatedRuntimeClient {
    fn session_info(&self) -> &runne_runtime_client::RuntimeSessionInfo {
        Self::session_info(self)
    }

    fn read_mode_status(
        &self,
        workspace_id: CanonicalId,
    ) -> ModeFuture<'_, PermissionModeStatusV1> {
        Box::pin(async move {
            Self::permission_mode_status(self, workspace_id)
                .await
                .map_err(ModeApiError::from_runtime)
        })
    }

    fn read_mode_command(
        &self,
        workspace_id: CanonicalId,
        command_id: CanonicalId,
    ) -> ModeFuture<'_, PermissionModeCommandStatusV2> {
        Box::pin(async move {
            Self::permission_mode_command_status(self, workspace_id, command_id)
                .await
                .map_err(ModeApiError::from_runtime)
        })
    }

    fn request_permission_mode_change(
        &self,
        request: runne_runtime_client::PermissionModeChangeRequestV1,
    ) -> ModeFuture<'_, PermissionModeCommandStatusV2> {
        Box::pin(async move {
            Self::request_permission_mode_change(self, request)
                .await
                .map_err(ModeApiError::from_runtime)
        })
    }
}

include!("permissions/parse.rs");
include!("permissions/render.rs");
include!("permissions/help.rs");
include!("permissions/recovery_index.rs");
include!("permissions/approval_recovery.rs");
#[cfg(target_os = "linux")]
include!("permissions/recovery_io_linux.rs");
include!("permissions/mode.rs");
include!("permissions/approval_runtime.rs");
include!("permissions/approval_confirmation.rs");
include!("permissions/approval_response.rs");

#[expect(
    clippy::future_not_send,
    reason = "the CLI polls this command future inline and its runtime adapter remains local"
)]
async fn execute_permissions<R: PermissionsRuntime>(
    runtime: &R,
    command: PermissionsCommand,
) -> Result<CommandOutput, CliError> {
    match command {
        PermissionsCommand::Status { workspace_id } => runtime
            .permission_mode_status(workspace_id)
            .await
            .map(render_permission_mode_status)
            .map_err(CliError::Api),
        PermissionsCommand::CommandStatus {
            workspace_id,
            command_id,
        } => runtime
            .permission_mode_command_status(workspace_id, command_id)
            .await
            .map(render_permission_command_status)
            .map_err(CliError::Api),
        PermissionsCommand::ApprovalsList => runtime
            .list_pending_approvals()
            .await
            .map(render_pending_approvals)
            .map_err(CliError::Api),
    }
}

#[expect(
    clippy::future_not_send,
    reason = "approval confirmation runs inline on the CLI main thread"
)]
async fn run_permissions(
    profile_path: Option<PathBuf>,
    arguments: VecDeque<OsString>,
) -> Result<CommandOutput, CliError> {
    let command = parse_permissions(arguments)?;
    let client = connect_exec_client(profile_path).await?;
    match command {
        ParsedPermissionsCommand::Read(command) => execute_permissions(&client, command).await,
        ParsedPermissionsCommand::ModeSet(intent) => {
            execute_permission_mode_set(&client, intent).await
        }
        ParsedPermissionsCommand::ApprovalRespond(intent) => {
            execute_approval_response(&client, intent).await
        }
    }
}
