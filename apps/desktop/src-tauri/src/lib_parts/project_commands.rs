#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateRuntimeProjectRequest {
    display_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectMutationResponse {
    project_id: String,
    new_version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpenRuntimeWorkspaceRequest {
    workspace_id: String,
    expected_version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RenameRuntimeProjectRequest {
    project_id: String,
    expected_version: u64,
    display_name: String,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn create_runtime_project(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    request: CreateRuntimeProjectRequest,
) -> Result<ProjectMutationResponse, IpcError> {
    require_runtime_admission(&lifecycle)?;
    if !valid_project_name(&request.display_name) {
        return Err(IpcError {
            code: "project_creation_rejected",
        });
    }
    let project_id = runne_app_core::CanonicalId::now_v7();
    let acknowledgement = state
        .create_runtime_project(project_id, request.display_name)
        .await
        .map_err(|_| IpcError {
            code: "project_creation_rejected",
        })?;
    if acknowledgement.project_id() != project_id {
        return Err(IpcError {
            code: "project_creation_rejected",
        });
    }
    Ok(ProjectMutationResponse {
        project_id: project_id.to_string(),
        new_version: acknowledgement.new_version(),
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn rename_runtime_project(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    request: RenameRuntimeProjectRequest,
) -> Result<ProjectMutationResponse, IpcError> {
    require_runtime_admission(&lifecycle)?;
    let project_id =
        runne_app_core::CanonicalId::parse(&request.project_id).map_err(|_| IpcError {
            code: "project_update_rejected",
        })?;
    if request.expected_version == 0 || !valid_project_name(&request.display_name) {
        return Err(IpcError {
            code: "project_update_rejected",
        });
    }
    let acknowledgement = state
        .rename_runtime_project(project_id, request.expected_version, request.display_name)
        .await
        .map_err(|_| IpcError {
            code: "project_update_rejected",
        })?;
    if acknowledgement.project_id() != project_id {
        return Err(IpcError {
            code: "project_update_rejected",
        });
    }
    Ok(ProjectMutationResponse {
        project_id: project_id.to_string(),
        new_version: acknowledgement.new_version(),
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn create_runtime_workspace(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    request: CreateRuntimeWorkspaceRequest,
) -> Result<WorkspaceMutationResponse, IpcError> {
    require_runtime_admission(&lifecycle)?;
    let project_id =
        runne_app_core::CanonicalId::parse(&request.project_id).map_err(|_| IpcError {
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

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn open_runtime_workspace(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    request: OpenRuntimeWorkspaceRequest,
) -> Result<WorkspaceMutationResponse, IpcError> {
    require_runtime_admission(&lifecycle)?;
    let workspace_id =
        runne_app_core::CanonicalId::parse(&request.workspace_id).map_err(|_| IpcError {
            code: "workspace_open_rejected",
        })?;
    if request.expected_version == 0 {
        return Err(IpcError {
            code: "workspace_open_rejected",
        });
    }
    let acknowledgement = state
        .open_runtime_workspace(workspace_id, request.expected_version)
        .await
        .map_err(|_| IpcError {
            code: "workspace_open_rejected",
        })?;
    if acknowledgement.workspace_id() != workspace_id {
        return Err(IpcError {
            code: "workspace_open_rejected",
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

fn valid_project_name(value: &str) -> bool {
    valid_workspace_name(value)
}

#[cfg(test)]
mod project_command_tests {
    use super::{valid_project_name, valid_workspace_name};

    #[test]
    fn project_and_workspace_names_are_bounded_and_control_free() {
        assert!(valid_project_name("Selected folder"));
        assert!(valid_workspace_name("Workspace"));
        assert!(!valid_project_name(""));
        assert!(!valid_workspace_name("\u{0000}"));
        assert!(!valid_project_name(&"x".repeat(257)));
    }
}
