use std::future::Future;

use crate::ApiPrincipalId;
use runne_domain::id::{CommandId, WorkspaceId};

use super::{
    PermissionModeCommandStatusV3, PermissionModeHostErrorV1, PermissionModeStatusV2,
    ValidatedPermissionModeChangeV1,
};

/// V3 control-port errors preserve legacy host codes and fail closed on unsupported contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionModeControlHostErrorV3 {
    Host(PermissionModeHostErrorV1),
    ContractUnsupported,
}

impl PermissionModeControlHostErrorV3 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Host(error) => error.code(),
            Self::ContractUnsupported => "permission_mode_contract_unsupported",
        }
    }
}

/// Data-only asynchronous port for V3 status and command readback.
///
/// It accepts the unchanged, validated V1 caller intent and never carries
/// confirmation proof, principal intent, or new authorization authority.
pub trait PermissionModeControlHostV3: Send + Sync {
    fn status_v3(
        &self,
        principal: ApiPrincipalId,
        workspace_id: WorkspaceId,
    ) -> impl Future<Output = Result<PermissionModeStatusV2, PermissionModeControlHostErrorV3>> + Send;

    fn request_mode_change_v3(
        &self,
        principal: ApiPrincipalId,
        request: ValidatedPermissionModeChangeV1,
    ) -> impl Future<
        Output = Result<PermissionModeCommandStatusV3, PermissionModeControlHostErrorV3>,
    > + Send;

    fn command_status_v3(
        &self,
        principal: ApiPrincipalId,
        workspace_id: WorkspaceId,
        command_id: CommandId,
    ) -> impl Future<
        Output = Result<PermissionModeCommandStatusV3, PermissionModeControlHostErrorV3>,
    > + Send;
}
