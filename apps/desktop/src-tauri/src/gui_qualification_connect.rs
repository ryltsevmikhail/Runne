use std::sync::atomic::{AtomicUsize, Ordering};

use runne_app_core::{AppCore, RuntimeAvailability};
use serde_json::json;

static LIVE_CONNECT_HOOK_COUNT: AtomicUsize = AtomicUsize::new(0);

impl super::GuiQualificationControl {
    pub(crate) async fn after_runtime_connected(&self, core: &AppCore) -> Result<(), String> {
        runne_app_core::test_support::ensure_managed_task_run_gui_workspace(
            core,
            &self.project_id,
            &self.workspace_id,
        )
        .await
        .map_err(|_| "canonical GUI workspace fixture unavailable".to_owned())?;
        let connect_hook_count = LIVE_CONNECT_HOOK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        let marker = json!({
            "phase": self.phase,
            "workspaceId": self.workspace_id,
            "window": "native-tauri-webview",
            "availability": RuntimeAvailability::Live,
            "successfulLiveConnectHooks": connect_hook_count,
        });
        self.write_marker("gui-ready.json", &marker)?;
        self.write_marker(&format!("gui-ready-{}.json", self.phase), &marker)
    }
}
