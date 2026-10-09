use super::support::*;
use crate::ApiPrincipalId;
use runne_domain::id::WorkspaceId;
use std::future::Future;

struct UnsupportedHost;

impl PermissionModeControlHostV3 for UnsupportedHost {
    fn status_v3(
        &self,
        _principal: ApiPrincipalId,
        _workspace_id: WorkspaceId,
    ) -> impl Future<Output = Result<PermissionModeStatusV2, PermissionModeControlHostErrorV3>> + Send
    {
        std::future::ready(Err(PermissionModeControlHostErrorV3::ContractUnsupported))
    }

    fn request_mode_change_v3(
        &self,
        _principal: ApiPrincipalId,
        _request: ValidatedPermissionModeChangeV1,
    ) -> impl Future<
        Output = Result<PermissionModeCommandStatusV3, PermissionModeControlHostErrorV3>,
    > + Send {
        std::future::ready(Err(PermissionModeControlHostErrorV3::ContractUnsupported))
    }

    fn command_status_v3(
        &self,
        _principal: ApiPrincipalId,
        _workspace_id: WorkspaceId,
        _command_id: CommandId,
    ) -> impl Future<
        Output = Result<PermissionModeCommandStatusV3, PermissionModeControlHostErrorV3>,
    > + Send {
        std::future::ready(Err(PermissionModeControlHostErrorV3::ContractUnsupported))
    }
}

fn assert_send_future<T, F>(future: F)
where
    F: Future<Output = Result<T, PermissionModeControlHostErrorV3>> + Send,
{
    drop(future);
}

#[test]
fn v3_port_is_send_sync_and_reuses_the_validated_v1_caller_intent() {
    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    let host = UnsupportedHost;
    assert_send_sync(&host);
    let principal = ApiPrincipalId::new("authenticated-principal").expect("principal");
    let workspace_id = WorkspaceId::from_bytes(ID_BYTES);
    let request = PermissionModeChangeRequestV1::new(
        workspace_id,
        command_id(),
        "v3-control-test",
        4,
        PermissionModeV1::RiskBased,
        1,
        None,
    )
    .validate()
    .expect("validated V1 request");

    assert_send_future::<PermissionModeStatusV2, _>(
        host.status_v3(principal.clone(), workspace_id),
    );
    assert_send_future::<PermissionModeCommandStatusV3, _>(
        host.request_mode_change_v3(principal.clone(), request),
    );
    assert_send_future::<PermissionModeCommandStatusV3, _>(host.command_status_v3(
        principal,
        workspace_id,
        command_id(),
    ));
}

#[test]
fn unsupported_contract_has_a_stable_code_and_host_errors_keep_v1_codes() {
    assert_eq!(
        PermissionModeControlHostErrorV3::ContractUnsupported.code(),
        "permission_mode_contract_unsupported"
    );
    assert_eq!(
        PermissionModeControlHostErrorV3::Host(PermissionModeHostErrorV1::Unavailable).code(),
        PermissionModeHostErrorV1::Unavailable.code()
    );
}
