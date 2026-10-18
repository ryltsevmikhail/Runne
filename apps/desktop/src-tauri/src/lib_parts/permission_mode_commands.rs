#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn get_permission_mode_status(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
) -> Result<runne_api::PermissionModeStatusV1, IpcError> {
    state
        .permission_mode_status(&workspace_id)
        .await
        .map_err(|_| IpcError {
            code: "permission_mode_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn request_permission_mode_change(
    state: State<'_, Arc<AppCore>>,
    request: runne_api::PermissionModeChangeRequestV1,
) -> Result<runne_api::PermissionModeCommandStatusV2, IpcError> {
    state
        .request_permission_mode_change(request)
        .await
        .map_err(|_| IpcError {
            code: "permission_mode_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn get_permission_mode_command_status(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
    command_id: String,
) -> Result<runne_api::PermissionModeCommandStatusV2, IpcError> {
    state
        .permission_mode_command_status(&workspace_id, &command_id)
        .await
        .map_err(|error| IpcError {
            code: permission_command_status_error_code(&error),
        })
}

const fn permission_command_status_error_code(error: &AppCoreError) -> &'static str {
    match error {
        AppCoreError::PermissionCommandUnknown => "permission_command_unknown",
        _ => "permission_command_unavailable",
    }
}

#[cfg(test)]
mod permission_mode_command_error_tests {
    use super::permission_command_status_error_code;
    use crate::AppCoreError;

    #[test]
    fn command_readback_keeps_unknown_distinct_from_unavailable() {
        assert_eq!(
            permission_command_status_error_code(&AppCoreError::PermissionCommandUnknown),
            "permission_command_unknown"
        );
        assert_eq!(
            permission_command_status_error_code(&AppCoreError::RuntimeUnavailable),
            "permission_command_unavailable"
        );
        assert_eq!(
            permission_command_status_error_code(&AppCoreError::InvalidMutation),
            "permission_command_unavailable"
        );
    }
}
