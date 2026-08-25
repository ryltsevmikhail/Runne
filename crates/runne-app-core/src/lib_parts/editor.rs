impl AppCore {
    /// Opens one runtime-authorized Workspace-relative file in the system editor.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid IDs/path, missing capability, stale
    /// admission, or unavailable native editor support.
    pub async fn open_workspace_editor(
        &self,
        workspace_id: &str,
        relative_path: &str,
    ) -> Result<CanonicalEditorLaunchReceipt, AppCoreError> {
        let workspace_id = parse_process_id(workspace_id)?;
        let identity = process_command_identity()?;
        let request = runne_runtime_client::OpenEditorCommandRequest::new(
            identity,
            workspace_id,
            relative_path,
            runne_runtime_client::EditorLaunchTargetDto::SystemDefault,
        )
        .map_err(|_| AppCoreError::InvalidMutation)?;
        let _operation = self.runtime_operation.lock().await;
        let receipt = self
            .live_runtime_client()?
            .open_workspace_editor(request)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(CanonicalEditorLaunchReceipt {
            workspace_id: receipt.workspace_id().to_string(),
            target: "system_default",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalEditorLaunchReceipt {
    pub workspace_id: String,
    pub target: &'static str,
}
