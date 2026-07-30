mod bundled_runtime;
pub mod conversation_channel;

use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub use bundled_runtime::{BundledRuntimeController, BundledShutdownOutcome};
use conversation_channel::{
    ConversationChannelError, ConversationChannelEvent, ConversationSubscriptionManager,
};
use gocode_app_core::{
    AppCore, AppCoreError, BootstrapState, ConversationSnapshot, DiagnosticsSnapshot,
    ProjectSummary, RuntimeAvailability, RuntimeFailureCode, RuntimeMode,
};
use gocode_platform_desktop::ProfileLock;
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

fn require_runtime_admission(lifecycle: &RuntimeLifecycleManager) -> Result<(), IpcError> {
    if lifecycle.is_shutting_down() {
        return Err(IpcError {
            code: "runtime_shutdown_in_progress",
        });
    }
    Ok(())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_bootstrap(state: State<'_, Arc<AppCore>>) -> Result<BootstrapState, IpcError> {
    state.bootstrap().map_err(|_| IpcError {
        code: "bootstrap_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn set_theme(state: State<'_, Arc<AppCore>>, theme: String) -> Result<(), IpcError> {
    state.set_theme(&theme).map_err(|_| IpcError {
        code: "theme_update_rejected",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn list_projects(state: State<'_, Arc<AppCore>>) -> Result<Vec<ProjectSummary>, IpcError> {
    state.list_projects().map_err(|_| IpcError {
        code: "projects_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_project(
    state: State<'_, Arc<AppCore>>,
    id: i64,
) -> Result<Option<ProjectSummary>, IpcError> {
    state.get_project(id).map_err(|_| IpcError {
        code: "project_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn open_local_project(
    state: State<'_, Arc<AppCore>>,
    path: String,
) -> Result<ProjectSummary, IpcError> {
    state
        .open_local_project(Path::new(&path))
        .map_err(|_| IpcError {
            code: "project_open_rejected",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_diagnostics(state: State<'_, Arc<AppCore>>) -> Result<DiagnosticsSnapshot, IpcError> {
    state
        .diagnostics(env!("CARGO_PKG_VERSION"), std::env::consts::OS)
        .map_err(|_| IpcError {
            code: "diagnostics_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn connect_runtime(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
) -> Result<RuntimeAvailability, IpcError> {
    require_runtime_admission(&lifecycle)?;
    lifecycle
        .connect_runtime(&state)
        .await
        .map_err(|_| IpcError {
            code: "runtime_connection_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn open_project_conversation(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    project_id: i64,
) -> Result<ConversationSnapshot, IpcError> {
    require_runtime_admission(&lifecycle)?;
    state
        .open_project_conversation(project_id)
        .await
        .map_err(|_| IpcError {
            code: "conversation_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn resync_project_conversation(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    project_id: i64,
) -> Result<ConversationSnapshot, IpcError> {
    require_runtime_admission(&lifecycle)?;
    state
        .resync_project_conversation(project_id)
        .await
        .map_err(|_| IpcError {
            code: "replay_resync_required",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn send_project_message(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    project_id: i64,
    text: String,
) -> Result<ConversationSnapshot, IpcError> {
    require_runtime_admission(&lifecycle)?;
    state
        .send_project_message(project_id, &text)
        .await
        .map_err(|_| IpcError {
            code: "conversation_message_rejected",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn subscribe_project_conversation(
    window: WebviewWindow,
    core: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    project_id: i64,
    on_update: Channel<ConversationChannelEvent>,
) -> Result<String, ConversationChannelError> {
    if lifecycle.is_shutting_down() {
        return Err(ConversationChannelError::unavailable());
    }
    subscriptions.subscribe(
        Arc::clone(core.inner()),
        project_id,
        window.label(),
        on_update,
    )
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn ack_conversation_update(
    window: WebviewWindow,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    subscription_id: String,
    projection_revision: u64,
) -> Result<(), ConversationChannelError> {
    if lifecycle.is_shutting_down() {
        return Err(ConversationChannelError::unavailable());
    }
    subscriptions.ack(window.label(), &subscription_id, projection_revision)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn cancel_conversation_subscription(
    window: WebviewWindow,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    subscription_id: String,
) -> Result<(), ConversationChannelError> {
    if lifecycle.is_shutting_down() {
        return Err(ConversationChannelError::unavailable());
    }
    subscriptions.cancel(window.label(), &subscription_id)
}

/// Starts the native desktop application.
///
/// # Panics
///
/// Panics when Tauri cannot initialize or run the application event loop.
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .on_window_event(|window, event| {
            if matches!(event, WindowEvent::Destroyed) {
                window
                    .state::<ConversationSubscriptionManager>()
                    .cancel_window(window.label());
            }
        })
        .setup(|app| {
            let profile_directory = app.path().app_data_dir()?;
            std::fs::create_dir_all(&profile_directory)?;
            let profile_lock = ProfileLock::acquire(&profile_directory.join("profile.lock"))?;
            let runtime_mode = select_runtime_mode(std::env::args_os().skip(1))?;
            let core = Arc::new(AppCore::open_with_runtime_mode(
                &profile_directory.join("profile.sqlite3"),
                runtime_mode,
            )?);
            let lifecycle = match runtime_mode {
                RuntimeMode::ExternalLocal => RuntimeLifecycleManager::external(),
                RuntimeMode::Bundled => {
                    let controller = std::env::current_exe()
                        .map_err(|_| RuntimeFailureCode::BundledExecutableUnavailable)
                        .and_then(|desktop_executable| {
                            BundledRuntimeController::discover(
                                Arc::clone(&core),
                                &desktop_executable,
                                &profile_directory.join("bundled-runtime"),
                            )
                        });
                    match controller {
                        Ok(controller) => {
                            controller.spawn_monitor();
                            RuntimeLifecycleManager::bundled(controller)
                        }
                        Err(failure) => {
                            tauri::async_runtime::block_on(
                                core.mark_bundled_runtime_failed(failure),
                            )?;
                            RuntimeLifecycleManager::bundled_unavailable()
                        }
                    }
                }
            };
            app.manage(profile_lock);
            app.manage(core);
            app.manage(ConversationSubscriptionManager::new());
            app.manage(lifecycle);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_bootstrap,
            set_theme,
            list_projects,
            get_project,
            open_local_project,
            get_diagnostics,
            connect_runtime,
            open_project_conversation,
            resync_project_conversation,
            send_project_message,
            subscribe_project_conversation,
            ack_conversation_update,
            cancel_conversation_subscription
        ])
        .build(tauri::generate_context!())
        .expect("failed to initialize GOCODE desktop application");
    app.run(|app, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            let lifecycle = app.state::<RuntimeLifecycleManager>();
            if lifecycle.begin_explicit_quit() {
                app.state::<ConversationSubscriptionManager>().shutdown();
                lifecycle.stop_owned_runtime();
            }
        }
    });
}
