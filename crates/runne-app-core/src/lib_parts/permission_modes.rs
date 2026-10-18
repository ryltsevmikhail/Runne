use runne_api::{
    PermissionModeChangeRequestV1, PermissionModeCommandStatusV2,
    PermissionModeNativePendingPageV2, PermissionModeStatusV1,
};

impl AppCore {
    /// Reads the runtime-owned selected/effective mode projection for a workspace.
    ///
    /// # Errors
    /// Returns `InvalidMutation` for a noncanonical workspace ID or `RuntimeUnavailable`
    /// if the authenticated runtime cannot provide the projection.
    pub async fn permission_mode_status(
        &self,
        workspace_id: &str,
    ) -> Result<PermissionModeStatusV1, AppCoreError> {
        let workspace_id =
            CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::InvalidMutation)?;
        let _operation = self.runtime_operation.lock().await;
        self.live_runtime_client()?
            .permission_mode_status(workspace_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    /// Sends one typed caller intent through the authenticated runtime client.
    ///
    /// # Errors
    /// Returns `RuntimeUnavailable` if the authenticated runtime cannot process the request.
    pub async fn request_permission_mode_change(
        &self,
        request: PermissionModeChangeRequestV1,
    ) -> Result<PermissionModeCommandStatusV2, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.live_runtime_client()?
            .request_permission_mode_change(request)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    /// Reads current-session mode requests discovered through the authenticated runtime.
    ///
    /// # Errors
    /// Returns `RuntimeUnavailable` if the authenticated runtime cannot provide the queue page.
    pub async fn permission_mode_native_pending(
        &self,
        after: Option<CanonicalId>,
    ) -> Result<PermissionModeNativePendingPageV2, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.live_runtime_client()?
            .permission_mode_native_pending(after)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    /// Reads the durable result for the same public command identity.
    ///
    /// # Errors
    /// Returns `InvalidMutation` for noncanonical IDs or `RuntimeUnavailable` if the runtime
    /// cannot provide command readback.
    pub async fn permission_mode_command_status(
        &self,
        workspace_id: &str,
        command_id: &str,
    ) -> Result<PermissionModeCommandStatusV2, AppCoreError> {
        let workspace_id =
            CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::InvalidMutation)?;
        let command_id =
            CanonicalId::parse(command_id).map_err(|_| AppCoreError::InvalidMutation)?;
        let _operation = self.runtime_operation.lock().await;
        self.live_runtime_client()?
            .permission_mode_command_status(workspace_id, command_id)
            .await
            .map_err(|error| match error.kind() {
                RuntimeApiErrorKind::NotFound => AppCoreError::PermissionCommandUnknown,
                _ => AppCoreError::RuntimeUnavailable,
            })
    }
}
