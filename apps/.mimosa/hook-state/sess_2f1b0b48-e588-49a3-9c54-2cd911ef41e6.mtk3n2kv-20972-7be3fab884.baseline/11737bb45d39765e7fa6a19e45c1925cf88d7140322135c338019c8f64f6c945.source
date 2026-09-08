#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn list_workspace_changes(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
    limit: u16,
) -> Result<CanonicalWorkspaceChangeSet, IpcError> {
    state
        .list_workspace_changes(&workspace_id, limit)
        .await
        .map_err(|_| IpcError {
            code: "workspace_changes_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn read_workspace_diff(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
    path: String,
) -> Result<CanonicalWorkspaceDiff, IpcError> {
    state
        .read_workspace_diff(&workspace_id, &path)
        .await
        .map_err(|_| IpcError {
            code: "workspace_diff_unavailable",
        })
}
