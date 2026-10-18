impl PermissionModeRuntime for ProtectedPermissionsRuntime<'_> {
    fn session_info(&self) -> &runne_runtime_client::RuntimeSessionInfo {
        self.client.session_info()
    }
    fn read_mode_status(
        &self,
        workspace_id: CanonicalId,
    ) -> ModeFuture<'_, PermissionModeStatusV1> {
        Box::pin(async move {
            let status = self.client.permission_mode_status(workspace_id).await;
            status.map_err(ModeApiError::from_runtime)
        })
    }
    fn read_mode_command(
        &self,
        workspace_id: CanonicalId,
        command_id: CanonicalId,
    ) -> ModeFuture<'_, PermissionModeCommandStatusV2> {
        Box::pin(async move {
            self.client
                .permission_mode_command_status(workspace_id, command_id)
                .await
                .map_err(ModeApiError::from_runtime)
        })
    }
    fn request_permission_mode_change(
        &self,
        request: runne_runtime_client::PermissionModeChangeRequestV1,
    ) -> ModeFuture<'_, PermissionModeCommandStatusV2> {
        Box::pin(async move {
            #[cfg(test)]
            super::protected_runtime_tests::barrier("before_post");
            let validated = request
                .clone()
                .validate()
                .map_err(|_| unavailable_mode_error())?;
            let response = self.client.request_permission_mode_change(request).await;
            let status = response.map_err(ModeApiError::from_runtime)?;
            if !matches!(
                &status,
                PermissionModeCommandStatusV2::PendingNativeConfirmation { .. }
                    | PermissionModeCommandStatusV2::PendingReauthentication { .. }
            ) {
                return Ok(status);
            }
            let page = self
                .client
                .permission_mode_native_pending(None)
                .await
                .map_err(ModeApiError::from_runtime)?;
            let command_id = validated.command_id().to_string();
            let pending = page
                .pending
                .into_iter()
                .find(|item| item.context.command_id == command_id)
                .ok_or_else(unavailable_mode_error)?;
            match self.native_consent(&pending, validated.requested_mode()) {
                Ok(true) => {}
                Ok(false) => self.cancel_native_exchange()?,
                Err(error) => {
                    let _ = self.cancel_native_exchange();
                    return Err(error);
                }
            }
            #[cfg(test)]
            super::protected_runtime_tests::barrier("after_commit");
            let workspace_id = CanonicalId::parse(&validated.workspace_id().to_string())
                .map_err(|_| unavailable_mode_error())?;
            let command_id = CanonicalId::parse(&validated.command_id().to_string())
                .map_err(|_| unavailable_mode_error())?;
            self.client
                .permission_mode_command_status(workspace_id, command_id)
                .await
                .map_err(ModeApiError::from_runtime)
        })
    }
}
impl ProtectedPermissionsRuntime<'_> {
    fn native_consent(
        &self,
        pending: &PermissionModeNativePendingV2,
        requested: runne_runtime_client::PermissionModeV1,
    ) -> Result<bool, ModeApiError> {
        #[cfg(not(test))]
        let context = pending
            .context
            .control_context()
            .map_err(|_| unavailable_mode_error())?;
        let challenge = self
            .supervisor
            .lock()
            .map_err(|_| unavailable_mode_error())?
            .request_permission_mode_challenge(pending)
            .map_err(|_| unavailable_mode_error())?;
        if challenge.requested_mode != permission_selection(requested) {
            return Err(unavailable_mode_error());
        }
        #[cfg(test)]
        return super::protected_runtime_tests::mock_native_consent(
            self,
            challenge.ceremony_expires_at_unix_ms,
        );
        #[cfg(not(test))]
        {
            let Ok(warning) =
                runne_platform_desktop::permission_reauth_linux::request_native_permission_warning(
                    &challenge,
                    &context,
                    self.scheduler.as_ref(),
                )
            else {
                return Ok(false);
            };
            let reauthentication =
                if challenge.requested_mode == runne_api::PermissionModeSelectionV1::FullAccess {
                    let Some(deadline) =
                        super::permission_ceremony_deadline(challenge.ceremony_expires_at_unix_ms)
                    else {
                        return Ok(false);
                    };
                    match runne_platform_desktop::permission_reauth_linux::reauthenticate(
                        challenge.issued_challenge_binding_digest,
                        deadline,
                        Arc::clone(&self.pam),
                    ) {
                        Ok(token) => Some(token),
                        Err(_) => return Ok(false),
                    }
                } else {
                    None
                };
            self.supervisor
                .lock()
                .map_err(|_| unavailable_mode_error())?
                .complete_permission_mode_consent(warning, reauthentication)
                .map_err(|_| unavailable_mode_error())?;
            Ok(true)
        }
    }
    fn cancel_native_exchange(&self) -> Result<(), ModeApiError> {
        self.supervisor
            .lock()
            .map_err(|_| unavailable_mode_error())?
            .cancel_permission_mode()
            .map(|_| ())
            .map_err(|_| unavailable_mode_error())
    }
}
