use runne_platform_desktop::permission_reauth_linux::{
    NativePermissionWarningMainThreadScheduler, NativePermissionWarningUiTask,
};
use tauri::WebviewWindow;

pub(super) struct NativeWarningScheduler(WebviewWindow);

impl NativeWarningScheduler {
    pub(super) const fn new(window: WebviewWindow) -> Self {
        Self(window)
    }
}

impl NativePermissionWarningMainThreadScheduler for NativeWarningScheduler {
    fn schedule(&self, task: NativePermissionWarningUiTask) -> Result<(), ()> {
        let window = self.0.clone();
        let ui_window = window.clone();
        window
            .run_on_main_thread(move || match ui_window.gtk_window() {
                Ok(parent) => task.run(parent),
                Err(_) => task.cancel(),
            })
            .map_err(|_| ())
    }
}
