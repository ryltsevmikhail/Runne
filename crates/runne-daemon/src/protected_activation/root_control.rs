#[cfg(all(unix, feature = "desktop-protected"))]
use crate::application::root_handle_admission::RootAdmissionGateway;
use std::sync::Arc;

#[cfg(unix)]
use super::PermissionControlHost;
use crate::application::root_handle_admission::RootHandleAdmissionAuthority;
#[cfg(unix)]
use runne_api::ProtectedOwnedLaunchV1;
use runne_api::{
    ApiPrincipalId, LaunchAuthorityError, PermissionControlContextV1,
    PermissionControlModeConsentV1, PermissionControlResultV1, ProtectedActivationKeys,
};

#[cfg(feature = "desktop-protected")]
pub(crate) struct ProtectedRootControl {
    authority: Arc<RootHandleAdmissionAuthority>,
    #[cfg(unix)]
    permission_control: Option<PermissionControlHost>,
}

#[cfg(feature = "desktop-protected")]
impl ProtectedRootControl {
    pub(crate) fn new(authority: Arc<RootHandleAdmissionAuthority>) -> Arc<Self> {
        Arc::new(Self {
            authority,
            #[cfg(unix)]
            permission_control: None,
        })
    }

    #[cfg(unix)]
    pub(crate) fn new_with_permission_control(
        authority: Arc<RootHandleAdmissionAuthority>,
        permission_control: PermissionControlHost,
    ) -> Arc<Self> {
        Arc::new(Self {
            authority,
            permission_control: Some(permission_control),
        })
    }

    #[cfg(all(unix, feature = "desktop-protected"))]
    pub(crate) fn observe_permission_launch(
        &self,
        owned: &ProtectedOwnedLaunchV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if let Some(host) = &self.permission_control {
            host.observe_launch(owned, keys)?;
        }
        Ok(())
    }

    #[cfg(all(unix, feature = "desktop-protected"))]
    pub(crate) fn permission_mode_challenge(
        &self,
        principal: &runne_api::ApiPrincipalId,
        command_id: runne_domain::id::CommandId,
    ) -> Result<
        Option<(
            runne_api::PermissionControlContextV1,
            runne_api::PermissionControlModeChallengeV1,
        )>,
        LaunchAuthorityError,
    > {
        self.permission_control
            .as_ref()
            .map_or(Ok(None), |host| host.mode_challenge(principal, command_id))
    }

    #[cfg(all(unix, feature = "desktop-protected"))]
    pub(crate) fn finish_permission_mode(
        &self,
        principal: &ApiPrincipalId,
        workspace: runne_domain::id::WorkspaceId,
        context: &PermissionControlContextV1,
        consent: &PermissionControlModeConsentV1,
        keys: &ProtectedActivationKeys,
        now: u64,
    ) -> Result<Option<PermissionControlResultV1>, LaunchAuthorityError> {
        self.permission_control
            .as_ref()
            .map(|host| {
                host.finish_mode(
                    principal,
                    workspace,
                    context,
                    consent,
                    keys,
                    now,
                    &RootAdmissionGateway::protected(Arc::clone(&self.authority)),
                )
            })
            .transpose()
    }

    #[cfg(all(unix, feature = "desktop-protected"))]
    pub(crate) fn cancel_permission_mode(
        &self,
        principal: &ApiPrincipalId,
        workspace: runne_domain::id::WorkspaceId,
        context: &PermissionControlContextV1,
    ) -> Result<Option<PermissionControlResultV1>, LaunchAuthorityError> {
        self.permission_control
            .as_ref()
            .map(|host| host.cancel_mode(principal, workspace, context))
            .transpose()
    }

    pub(crate) fn rotate_enrollment_keys(
        &self,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), runne_application::ports::RootAdmissionVerifierError> {
        self.authority.rotate_enrollment_keys(keys)
    }

    pub(crate) fn admit_verified_offer(
        &self,
        offer: &runne_api::RootHandleTransferOffer,
        root: runne_platform_desktop::VerifiedRootHandle,
        now: u64,
    ) -> Result<
        crate::application::root_handle_admission::IssuedRootAdmission,
        runne_application::ports::RootAdmissionVerifierError,
    > {
        self.authority.admit(offer, root, now)
    }

    pub(crate) fn fence(&self) -> Result<(), runne_application::ports::RootAdmissionVerifierError> {
        self.authority.fence()
    }

    pub(crate) fn shutdown(&self) {
        self.authority.shutdown();
    }
}

#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) fn permission_mode_status_result(
    status: runne_store::store::PermissionModeCeremonyStatusV2,
    command_id: runne_domain::id::CommandId,
    public_request_digest: [u8; 32],
) -> Result<runne_api::PermissionControlResultV1, ()> {
    use runne_store::store::PermissionModeCeremonyStatusV2 as Status;
    let (code, receipt_digest, authorization_revision, managed_policy_revision) = match status {
        Status::Pending(_) => (
            runne_api::PermissionControlResultCodeV1::Pending,
            None,
            None,
            None,
        ),
        Status::Committed(receipt) => (
            runne_api::PermissionControlResultCodeV1::Committed,
            Some(*receipt.intent_digest.as_bytes()),
            Some(receipt.selection.authorization_revision),
            Some(receipt.projection.managed_policy_version),
        ),
        Status::Cancelled => (
            runne_api::PermissionControlResultCodeV1::Cancelled,
            None,
            None,
            None,
        ),
        Status::Expired => (
            runne_api::PermissionControlResultCodeV1::Expired,
            None,
            None,
            None,
        ),
        Status::Invalidated => (
            runne_api::PermissionControlResultCodeV1::Invalidated,
            None,
            None,
            None,
        ),
    };
    Ok(runne_api::PermissionControlResultV1 {
        code,
        command_id: command_id.into_bytes(),
        public_request_digest,
        receipt_digest,
        authorization_revision,
        managed_policy_revision,
    })
}
