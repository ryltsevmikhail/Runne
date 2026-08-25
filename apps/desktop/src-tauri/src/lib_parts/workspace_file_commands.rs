#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn list_workspace_files(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
    path: String,
    limit: u16,
) -> Result<CanonicalWorkspaceFilePage, IpcError> {
    state
        .list_workspace_files(&workspace_id, &path, limit)
        .await
        .map_err(|_| IpcError {
            code: "workspace_files_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn read_workspace_file(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
    path: String,
) -> Result<CanonicalWorkspaceFileContent, IpcError> {
    state
        .read_workspace_file(&workspace_id, &path)
        .await
        .map_err(|_| IpcError {
            code: "workspace_file_unavailable",
        })
}
