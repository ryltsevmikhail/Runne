use tauri::menu::{MenuBuilder, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

const TRAY_ID: &str = "runne-tray";
const SHOW_ID: &str = "tray-show";

const APP_ICON: tauri::image::Image<'static> = tauri::include_image!("icons/32x32.png");

/// Installs the host-owned tray lifecycle for the primary window.
pub fn install<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let menu = MenuBuilder::new(app)
        .text(SHOW_ID, "Show Runne")
        .separator()
        .item(&PredefinedMenuItem::quit(app, Some("Quit Runne"))?)
        .build()?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(APP_ICON)
        .menu(&menu)
        .tooltip("Runne")
        .on_menu_event(|app, event| {
            if event.id().as_ref() == SHOW_ID {
                show_main_window(app);
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}
