use gocode_app_core::{AppCore, BootstrapState};
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

/// Starts the native desktop application.
///
/// # Panics
///
/// Panics when Tauri cannot initialize or run the application event loop.
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let profile_directory = app.path().app_data_dir()?;
            std::fs::create_dir_all(&profile_directory)?;
            let core = AppCore::open(&profile_directory.join("profile.sqlite3"))?;
            app.manage(core);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_bootstrap, set_theme])
        .run(tauri::generate_context!())
        .expect("failed to run GOCODE desktop application");
}
