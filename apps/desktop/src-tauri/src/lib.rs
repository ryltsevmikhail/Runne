mod bundled_runtime;
pub mod conversation_channel;
mod directory_selection;
mod renderer_generation;

use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "test-support")]
pub use bundled_runtime::NativeOpenAiActivationTestGate;
pub use bundled_runtime::{BundledRuntimeController, BundledShutdownOutcome};
use conversation_channel::{
    ConversationChannelError, ConversationChannelEvent, ConversationSubscriptionManager,
};
pub use directory_selection::{DirectorySelectionManager, DirectorySelectionRef, SelectionError};
use gocode_app_core::{
    AppCore, AppCoreError, BootstrapState, ConversationSnapshot, DiagnosticsSnapshot,
    ProjectSummary, RuntimeAvailability, RuntimeFailureCode, RuntimeMode,
};
use gocode_platform_desktop::ProfileLock;
pub use gocode_platform_desktop::VerifiedRootHandle;
pub use renderer_generation::{RendererGenerationError, RendererGenerationManager};
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{Manager, RunEvent, State, WebviewWindow, WindowEvent};

#[derive(Serialize)]
struct IpcError {
    code: &'static str,
}

pub type RuntimeConnectionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RuntimeAvailability, AppCoreError>> + Send + 'a>>;

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

/// Renderer-private runtime lifecycle hook registered by the desktop host.
///
/// External runtimes have no controller and therefore remain an intentional
/// no-op. Bundled mode registers only a controller that proves the exact owned
/// launch before it signals or terminates it.
pub struct RuntimeLifecycleManager {
    owned_runtime: Option<Arc<dyn OwnedRuntimeLifecycle>>,
    runtime_mode: RuntimeMode,
    shutting_down: AtomicBool,
}

impl RuntimeLifecycleManager {
    #[must_use]
    pub const fn external() -> Self {
        Self {
            owned_runtime: None,
            runtime_mode: RuntimeMode::ExternalLocal,
            shutting_down: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn bundled(owned_runtime: Arc<dyn OwnedRuntimeLifecycle>) -> Self {
        Self {
            owned_runtime: Some(owned_runtime),
            runtime_mode: RuntimeMode::Bundled,
            shutting_down: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub const fn bundled_unavailable() -> Self {
        Self {
            owned_runtime: None,
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
include!("lib_parts/run.rs");
