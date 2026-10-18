use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use runne_api::{
    PermissionModeChangeRequestV1, PermissionModeCommandStatusV2, PermissionModeControlHostV2,
};
use runne_domain::id::{CommandId, WorkspaceId};
use std::str::FromStr;

use super::{PermissionModeControlHttpState, error};
use crate::{auth::AuthenticatedPrincipal, error::RequestId};

pub(super) async fn status<H: PermissionModeControlHostV2 + 'static>(
    State(state): State<PermissionModeControlHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(workspace): Path<String>,
) -> Response {
    let Ok(workspace) = WorkspaceId::from_str(&workspace) else {
        return error::invalid_request(&request_id);
    };
    match state
        .0
        .status(principal.as_api_principal().clone(), workspace)
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(failure) => error::host_error(failure, &request_id),
    }
}

pub(super) async fn request_mode_change<H: PermissionModeControlHostV2 + 'static>(
    State(state): State<PermissionModeControlHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    body: Result<Json<PermissionModeChangeRequestV1>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(workspace) = WorkspaceId::from_str(&workspace) else {
        return error::invalid_request(&request_id);
    };
    let Ok(Json(body)) = body else {
        return error::invalid_request(&request_id);
    };
    let request = match body.validate() {
        Ok(request) => request,
        Err(failure) => return error::host_error(failure, &request_id),
    };
    if request.workspace_id() != workspace
        || !one_header_matches(&headers, "x-command-id", &request.command_id().to_string())
        || !one_header_matches(
            &headers,
            "idempotency-key",
            request.idempotency_key().as_str(),
        )
    {
        return error::invalid_request(&request_id);
    }
    match state
        .0
        .request_mode_change(principal.as_api_principal().clone(), request.clone())
        .await
    {
        Ok(result) if command_id(&result) == request.command_id() => command_response(result),
        Ok(_) => error::response_mismatch(&request_id),
        Err(failure) => error::host_error(failure, &request_id),
    }
}

pub(super) async fn command_status<H: PermissionModeControlHostV2 + 'static>(
    State(state): State<PermissionModeControlHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path((workspace, command)): Path<(String, String)>,
) -> Response {
    let (Ok(workspace), Ok(command)) = (
        WorkspaceId::from_str(&workspace),
        CommandId::from_str(&command),
    ) else {
        return error::invalid_request(&request_id);
    };
    match state
        .0
        .command_status(principal.as_api_principal().clone(), workspace, command)
        .await
    {
        Ok(result) if command_id(&result) == command => Json(result).into_response(),
        Ok(_) => error::response_mismatch(&request_id),
        Err(failure) => error::host_error(failure, &request_id),
    }
}

fn one_header_matches(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    values.next().and_then(|value| value.to_str().ok()) == Some(expected) && values.next().is_none()
}

fn command_id(status: &PermissionModeCommandStatusV2) -> CommandId {
    match status {
        PermissionModeCommandStatusV2::PendingNativeConfirmation { command_id, .. }
        | PermissionModeCommandStatusV2::PendingReauthentication { command_id, .. }
        | PermissionModeCommandStatusV2::Cancelled { command_id }
        | PermissionModeCommandStatusV2::Expired { command_id }
        | PermissionModeCommandStatusV2::Invalidated { command_id } => *command_id,
        PermissionModeCommandStatusV2::Committed { receipt } => receipt.command_id,
    }
}

fn command_response(status: PermissionModeCommandStatusV2) -> Response {
    let code = match status {
        PermissionModeCommandStatusV2::PendingNativeConfirmation { .. }
        | PermissionModeCommandStatusV2::PendingReauthentication { .. } => StatusCode::ACCEPTED,
        _ => StatusCode::OK,
    };
    (code, Json(status)).into_response()
}
