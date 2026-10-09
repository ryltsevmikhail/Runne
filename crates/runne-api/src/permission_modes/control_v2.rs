use std::future::Future;

use crate::ApiPrincipalId;
use runne_domain::id::{CommandId, WorkspaceId};

use super::{
    PermissionModeCommandStatusV2, PermissionModeHostErrorV1, PermissionModeStatusV1,
    ValidatedPermissionModeChangeV1,
};

/// Authenticated status and command readback port for permission-mode control.
///
/// The principal must come from authenticated ingress. A mode request carries
/// caller intent only; it cannot confirm native interaction or provide proof.
pub trait PermissionModeControlHostV2: Send + Sync {
    fn status(
        &self,
        principal: ApiPrincipalId,
        workspace_id: WorkspaceId,
    ) -> impl Future<Output = Result<PermissionModeStatusV1, PermissionModeHostErrorV1>> + Send;

    fn request_mode_change(
        &self,
        principal: ApiPrincipalId,
        request: ValidatedPermissionModeChangeV1,
    ) -> impl Future<Output = Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1>> + Send;

    fn command_status(
        &self,
        principal: ApiPrincipalId,
        workspace_id: WorkspaceId,
        command_id: CommandId,
    ) -> impl Future<Output = Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1>> + Send;
}
