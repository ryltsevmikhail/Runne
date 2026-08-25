#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRuntimeWorkspaceRequest {
    project_id: String,
    display_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceMutationResponse {
    workspace_id: String,
    new_version: u64,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn create_runtime_workspace(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    request: CreateRuntimeWorkspaceRequest,
) -> Result<WorkspaceMutationResponse, IpcError> {
    require_runtime_admission(&lifecycle)?;
    let project_id = runne_app_core::CanonicalId::parse(&request.project_id).map_err(|_| IpcError {
        code: "workspace_creation_rejected",
    })?;
    if !valid_workspace_name(&request.display_name) {
        return Err(IpcError {
            code: "workspace_creation_rejected",
        });
    }
    let workspace_id = runne_app_core::CanonicalId::now_v7();
    let acknowledgement = state
        .create_runtime_workspace(project_id, workspace_id, request.display_name)
        .await
        .map_err(|_| IpcError {
            code: "workspace_creation_rejected",
        })?;
    if acknowledgement.workspace_id() != workspace_id {
        return Err(IpcError {
            code: "workspace_creation_rejected",
        });
    }
    Ok(WorkspaceMutationResponse {
        workspace_id: workspace_id.to_string(),
        new_version: acknowledgement.new_version(),
    })
}

fn valid_workspace_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
