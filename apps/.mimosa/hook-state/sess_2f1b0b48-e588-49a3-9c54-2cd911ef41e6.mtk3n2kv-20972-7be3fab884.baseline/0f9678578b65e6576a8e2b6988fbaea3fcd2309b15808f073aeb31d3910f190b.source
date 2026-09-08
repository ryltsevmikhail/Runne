#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn open_workspace_editor(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
    relative_path: String,
) -> Result<runne_app_core::CanonicalEditorLaunchReceipt, IpcError> {
    state
        .open_workspace_editor(&workspace_id, &relative_path)
        .await
        .map_err(|_| IpcError {
            code: "editor_unavailable",
        })
}
