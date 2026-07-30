pub mod conversation_channel;

use std::path::Path;
use std::sync::Arc;

use conversation_channel::{
    ConversationChannelError, ConversationChannelEvent, ConversationSubscriptionManager,
};
use gocode_app_core::{
    AppCore, BootstrapState, ConversationSnapshot, DiagnosticsSnapshot, ProjectSummary,
    RuntimeAvailability,
};
use gocode_platform_desktop::ProfileLock;
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{Manager, RunEvent, State, WebviewWindow, WindowEvent};

#[derive(Serialize)]
struct IpcError {
    code: &'static str,
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
async fn connect_runtime(state: State<'_, Arc<AppCore>>) -> Result<RuntimeAvailability, IpcError> {
    state.connect_runtime().await.map_err(|_| IpcError {
        code: "runtime_connection_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn open_project_conversation(
    state: State<'_, Arc<AppCore>>,
    project_id: i64,
) -> Result<ConversationSnapshot, IpcError> {
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
    project_id: i64,
) -> Result<ConversationSnapshot, IpcError> {
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
    project_id: i64,
    text: String,
) -> Result<ConversationSnapshot, IpcError> {
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
    subscriptions: State<'_, ConversationSubscriptionManager>,
    project_id: i64,
    on_update: Channel<ConversationChannelEvent>,
) -> Result<String, ConversationChannelError> {
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
    subscriptions: State<'_, ConversationSubscriptionManager>,
    subscription_id: String,
    projection_revision: u64,
) -> Result<(), ConversationChannelError> {
    subscriptions.ack(window.label(), &subscription_id, projection_revision)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn cancel_conversation_subscription(
    window: WebviewWindow,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    subscription_id: String,
) -> Result<(), ConversationChannelError> {
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
            let core = AppCore::open_with_default_runtime_profile(
                &profile_directory.join("profile.sqlite3"),
            )?;
            app.manage(profile_lock);
            app.manage(Arc::new(core));
            app.manage(ConversationSubscriptionManager::new());
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
            app.state::<ConversationSubscriptionManager>().shutdown();
        }
    });
}
