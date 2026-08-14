mod bundled_runtime;
pub mod conversation_channel;
mod destructive_intent;
mod directory_selection;
mod directory_selection_response;
mod open_selected_workspace_request;
mod operational_telemetry_command;
mod prepare_workspace_request;
mod prepared_workspace;
mod renderer_generation;
#[cfg(feature = "test-support")]
pub use bundled_runtime::NativeOpenAiActivationTestGate;
pub use bundled_runtime::{BundledRuntimeController, BundledShutdownOutcome};
use conversation_channel::ConversationSubscriptionManager;
use directory_selection::{DirectorySelectionManager, DirectorySelectionRef};
pub use directory_selection_response::DirectorySelectionResponse;
use gocode_app_core::{
    AppCore, AppCoreError, BootstrapState, DiagnosticsSnapshot, ProjectSummary,
    RuntimeAvailability, RuntimeFailureCode, RuntimeMode,
};
use gocode_platform_desktop::ProfileLock;
use gocode_platform_desktop::{ProtectedRootHandleAdmission, VerifiedRootHandle, WorkspaceId};
use open_selected_workspace_request::{
    OpenSelectedWorkspaceRequest, RetryOpenSelectedWorkspaceRequest,
};
use prepare_workspace_request::PrepareSelectedWorkspaceRequest;
use prepared_workspace::{
    PreparedWorkspaceBinding, PreparedWorkspaceManager, PreparedWorkspaceReservationGuard,
    PreparedWorkspaceResponse,
};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{Manager, RunEvent, State, WebviewWindow, WindowEvent};
use tauri_plugin_dialog::DialogExt;

#[derive(Serialize)]
struct IpcError {
    code: &'static str,
}

pub type RuntimeConnectionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RuntimeAvailability, AppCoreError>> + Send + 'a>>;
struct NativeRootAdmission {
    pub(crate) root: VerifiedRootHandle,
    pub(crate) admission: ProtectedRootHandleAdmission,
    operation_permit: tokio::sync::OwnedMutexGuard<()>,
}

impl NativeRootAdmission {
    fn into_parts(
        self,
    ) -> (
        VerifiedRootHandle,
        ProtectedRootHandleAdmission,
        tokio::sync::OwnedMutexGuard<()>,
    ) {
        (self.root, self.admission, self.operation_permit)
    }
}

type RootAdmissionFuture =
    Pin<Box<dyn Future<Output = Result<NativeRootAdmission, AppCoreError>> + Send + 'static>>;
type RootAdmissionReapFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Host-only lifecycle control for a runtime proven owned by this desktop.
///
/// Implementations must retain ownership evidence internally and must not
/// report runtime work cancellation merely because shutdown was requested.
pub trait OwnedRuntimeLifecycle: Send + Sync {
    /// Connects only through the controller's protected native path.
    fn connect_runtime(&self) -> RuntimeConnectionFuture<'_> {
        Box::pin(async { Err(AppCoreError::RuntimeUnavailable) })
    }

    /// Runs the explicit-quit shutdown sequence for the proven owned runtime.
    fn stop_on_explicit_quit(&self);
}

trait NativeRootAdmissionLifecycle: OwnedRuntimeLifecycle {
    fn prepare_root_admission(
        &self,
        root: VerifiedRootHandle,
        workspace_id: WorkspaceId,
        expected_version: u64,
    ) -> RootAdmissionFuture;

    fn reap_failed_root_admission(
        &self,
        permit: tokio::sync::OwnedMutexGuard<()>,
    ) -> RootAdmissionReapFuture;
}

/// Renderer-private runtime lifecycle hook registered by the desktop host.
///
/// External runtimes have no controller and therefore remain an intentional
/// no-op. Bundled mode registers only a controller that proves the exact owned
/// launch before it signals or terminates it.
pub struct RuntimeLifecycleManager {
    owned_runtime: Option<Arc<dyn OwnedRuntimeLifecycle>>,
    root_admission: Option<Arc<dyn NativeRootAdmissionLifecycle>>,
    runtime_mode: RuntimeMode,
    shutting_down: AtomicBool,
}

impl RuntimeLifecycleManager {
    #[must_use]
    pub const fn external() -> Self {
        Self {
            owned_runtime: None,
            root_admission: None,
            runtime_mode: RuntimeMode::ExternalLocal,
            shutting_down: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn bundled(owned_runtime: Arc<dyn OwnedRuntimeLifecycle>) -> Self {
        Self {
            owned_runtime: Some(owned_runtime),
            root_admission: None,
            runtime_mode: RuntimeMode::Bundled,
            shutting_down: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub const fn bundled_unavailable() -> Self {
        Self {
            owned_runtime: None,
            root_admission: None,
            runtime_mode: RuntimeMode::Bundled,
            shutting_down: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub(crate) fn bundled_with_native_root(owned_runtime: Arc<BundledRuntimeController>) -> Self {
        Self {
            owned_runtime: Some(owned_runtime.clone()),
            root_admission: Some(owned_runtime),
            runtime_mode: RuntimeMode::Bundled,
            shutting_down: AtomicBool::new(false),
        }
    }

    /// Atomically fences new runtime commands. The caller that receives true
    /// owns the one-time explicit-quit sequence.
    pub fn begin_explicit_quit(&self) -> bool {
        self.shutting_down
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    /// Stops only a proven owned runtime; external runtime mode stays a no-op.
    pub fn stop_owned_runtime(&self) {
        if let Some(owned_runtime) = &self.owned_runtime {
            owned_runtime.stop_on_explicit_quit();
        }
    }

    /// Connects the selected mode without permitting bundled-to-external
    /// fallback.
    ///
    /// # Errors
    ///
    /// Returns a closed runtime error when shutdown is fenced or the selected
    /// controller is unavailable.
    pub async fn connect_runtime(
        &self,
        core: &AppCore,
    ) -> Result<RuntimeAvailability, AppCoreError> {
        if self.is_shutting_down() {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        match self.runtime_mode {
            RuntimeMode::ExternalLocal => core.connect_runtime().await,
            RuntimeMode::Bundled => match &self.owned_runtime {
                Some(owned_runtime) => owned_runtime.connect_runtime().await,
                None => Err(AppCoreError::RuntimeUnavailable),
            },
        }
    }

    /// Sends one native root to only the exact live bundled daemon.
    ///
    /// # Errors
    ///
    /// Returns a closed error for external, unavailable, or shutting-down runtime modes.
    pub(crate) async fn prepare_root_admission(
        &self,
        root: VerifiedRootHandle,
        workspace_id: WorkspaceId,
        expected_version: u64,
    ) -> Result<NativeRootAdmission, AppCoreError> {
        if self.is_shutting_down() {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        match &self.root_admission {
            Some(runtime) if self.runtime_mode == RuntimeMode::Bundled => {
                runtime
                    .prepare_root_admission(root, workspace_id, expected_version)
                    .await
            }
            _ => Err(AppCoreError::RuntimeUnavailable),
        }
    }

    /// Reaps only the current owned bundled child after an uncommitted admission.
    pub(crate) async fn reap_failed_root_admission(
        &self,
        permit: tokio::sync::OwnedMutexGuard<()>,
    ) {
        if let Some(runtime) = &self.root_admission {
            runtime.reap_failed_root_admission(permit).await;
        }
    }

    pub(crate) fn native_root_reaper(&self) -> Option<Arc<dyn NativeRootAdmissionLifecycle>> {
        self.root_admission.clone()
    }

    /// Fences host lifecycle work on explicit quit without adopting an
    /// external daemon.
    pub fn explicit_quit(&self) {
        if self.begin_explicit_quit() {
            self.stop_owned_runtime();
        }
    }
}

/// Closed rejection for conflicting native runtime-mode flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeModeSelectionError;

impl std::fmt::Display for RuntimeModeSelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("runtime mode selection rejected")
    }
}

impl std::error::Error for RuntimeModeSelectionError {}

/// Selects bundled mode by default; external mode requires an explicit native
/// flag. No profile or connection failure can change the selected mode.
///
/// # Errors
///
/// Returns a closed error when both mode flags are supplied.
pub fn select_runtime_mode<I>(arguments: I) -> Result<RuntimeMode, RuntimeModeSelectionError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut bundled = false;
    let mut external = false;
    for argument in arguments {
        if argument == OsStr::new("--bundled-runtime") {
            bundled = true;
        } else if argument == OsStr::new("--external-runtime") {
            external = true;
        }
    }
    if bundled && external {
        Err(RuntimeModeSelectionError)
    } else if external {
        Ok(RuntimeMode::ExternalLocal)
    } else {
        Ok(RuntimeMode::Bundled)
    }
}

include!("lib_parts/commands.rs");
include!("lib_parts/prepared_commit.rs");
include!("lib_parts/run.rs");
include!("lib_parts/test_modules.rs");
