#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn list_pending_approvals(
    state: State<'_, Arc<AppCore>>,
) -> Result<Vec<runne_app_core::CanonicalApprovalSummary>, IpcError> {
    state.list_pending_approvals().await.map_err(|_| IpcError {
        code: "approvals_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn get_approval(
    state: State<'_, Arc<AppCore>>,
    approval_id: String,
) -> Result<runne_app_core::CanonicalApprovalSummary, IpcError> {
    state.get_approval(&approval_id).await.map_err(|_| IpcError {
        code: "approval_unavailable",
    })
}
