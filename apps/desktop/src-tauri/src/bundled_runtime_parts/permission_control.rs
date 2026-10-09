use runne_api::{
    PermissionControlModeChallengeV1, PermissionControlResultV1, PermissionModeNativePendingV2,
};
use runne_platform_desktop::permission_reauth_linux::NativePermissionWarningConfirmationV1;

impl BundledRuntimeController {
    pub(crate) async fn request_permission_mode_challenge(
        &self,
        pending: PermissionModeNativePendingV2,
    ) -> Result<PermissionControlModeChallengeV1, ProtectedBundledRuntimeError> {
        let _operation = self
            .operation_fence
            .enter()
            .await
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        self.run_supervisor(move |supervisor| {
            supervisor.request_permission_mode_challenge(&pending)
        })
        .await
    }

    pub(crate) async fn complete_permission_mode_consent(
        &self,
        warning: NativePermissionWarningConfirmationV1,
        os_reauthentication: Option<
            runne_platform_desktop::permission_reauth_linux::FreshOsReauthentication,
        >,
    ) -> Result<PermissionControlResultV1, ProtectedBundledRuntimeError> {
        let _operation = self
            .operation_fence
            .enter()
            .await
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        self.run_supervisor(move |supervisor| {
            supervisor.complete_permission_mode_consent(warning, os_reauthentication)
        })
        .await
    }

    pub(crate) async fn cancel_permission_mode(
        &self,
    ) -> Result<PermissionControlResultV1, ProtectedBundledRuntimeError> {
        let _operation = self
            .operation_fence
            .enter()
            .await
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        self.run_supervisor(ProtectedBundledRuntimeSupervisor::cancel_permission_mode)
            .await
    }
}
