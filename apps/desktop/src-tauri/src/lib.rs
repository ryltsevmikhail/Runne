use std::path::Path;

use gocode_app_core::{AppCore, BootstrapState, DiagnosticsSnapshot, ProjectSummary};
use gocode_platform_desktop::ProfileLock;
use serde::Serialize;
use tauri::{Manager, State};

#[derive(Serialize)]
struct IpcError {
    code: &'static str,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_bootstrap(state: State<'_, AppCore>) -> Result<BootstrapState, IpcError> {
    state.bootstrap().map_err(|_| IpcError {
        code: "bootstrap_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn set_theme(state: State<'_, AppCore>, theme: String) -> Result<(), IpcError> {
    state.set_theme(&theme).map_err(|_| IpcError {
        code: "theme_update_rejected",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn list_projects(state: State<'_, AppCore>) -> Result<Vec<ProjectSummary>, IpcError> {
    state.list_projects().map_err(|_| IpcError {
        code: "projects_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_project(state: State<'_, AppCore>, id: i64) -> Result<Option<ProjectSummary>, IpcError> {
    state.get_project(id).map_err(|_| IpcError {
        code: "project_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn open_local_project(state: State<'_, AppCore>, path: String) -> Result<ProjectSummary, IpcError> {
    state
        .open_local_project(Path::new(&path))
        .map_err(|_| IpcError {
            code: "project_open_rejected",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_diagnostics(state: State<'_, AppCore>) -> Result<DiagnosticsSnapshot, IpcError> {
    state
        .diagnostics(env!("CARGO_PKG_VERSION"), std::env::consts::OS)
        .map_err(|_| IpcError {
            code: "diagnostics_unavailable",
        })
}

/// Starts the native desktop application.
///
/// # Panics
///
/// Panics when Tauri cannot initialize or run the application event loop.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let profile_directory = app.path().app_data_dir()?;
            std::fs::create_dir_all(&profile_directory)?;
            let profile_lock = ProfileLock::acquire(&profile_directory.join("profile.lock"))?;
            let core = AppCore::open(&profile_directory.join("profile.sqlite3"))?;
            app.manage(profile_lock);
            app.manage(core);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_bootstrap,
            set_theme,
            list_projects,
            get_project,
            open_local_project,
            get_diagnostics
        ])
        .run(tauri::generate_context!())
        .expect("failed to run GOCODE desktop application");
}
