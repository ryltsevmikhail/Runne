use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use gocode_api::{
    ExistingWorkspaceCommand, ProjectWorkspaceCommandHostPort, ProjectWorkspaceDisplayNameInput,
    ProjectWorkspaceQueryHostPort, RootHandleAdmission,
};
use gocode_domain::id::{ProjectId, WorkspaceId};

use super::helpers::{bad_request, context, host_error};
use crate::{
    auth::AuthenticatedPrincipal,
    error::RequestId,
    project_workspace::{ProjectWorkspaceHttpState, wire::*},
};
pub(crate) async fn create_workspace<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<CreateWorkspaceBody>, JsonRejection>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    let context = match context(&headers, &principal, &state.actor) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    let project_id = match project_id.parse::<ProjectId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_project_id", &request_id),
    };
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let workspace_id = match body.workspace_id.parse() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_workspace_id", &request_id),
    };
    let display_name = match ProjectWorkspaceDisplayNameInput::new(body.display_name) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_display_name", &request_id),
    };
    match state
        .host
        .create_workspace(
            context,
            gocode_api::CreateWorkspaceCommand {
                workspace_id,
                project_id,
                display_name,
            },
        )
        .await
    {
        Ok(ack) => (StatusCode::ACCEPTED, Json(WorkspaceAckWire::from(ack))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}
pub(crate) async fn open_workspace<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(workspace_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ExistingBody>, JsonRejection>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    let context = match context(&headers, &principal, &state.actor) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    let workspace_id = match workspace_id.parse::<WorkspaceId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_workspace_id", &request_id),
    };
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    if body.expected_version == 0 {
        return bad_request("invalid_expected_version", &request_id);
    }
    match state
        .host
        .open_workspace(
            context,
            ExistingWorkspaceCommand {
                workspace_id,
                expected_version: body.expected_version,
            },
        )
        .await
    {
        Ok(ack) => (StatusCode::ACCEPTED, Json(WorkspaceAckWire::from(ack))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}
pub(crate) async fn bind_workspace_root<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(workspace_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<RootBindingBody>, JsonRejection>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    let context = match context(&headers, &principal, &state.actor) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    let workspace_id = match workspace_id.parse::<WorkspaceId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_workspace_id", &request_id),
    };
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    if body.expected_version == 0 {
        return bad_request("invalid_expected_version", &request_id);
    }
    let root_admission = match RootHandleAdmission::decode_token(&body.root_admission) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_root_admission", &request_id),
    };
    match state
        .host
        .bind_workspace_root(
            context,
            gocode_api::BindWorkspaceRootCommand {
                workspace_id,
                expected_version: body.expected_version,
                root_admission,
            },
        )
        .await
    {
        Ok(ack) => (StatusCode::ACCEPTED, Json(WorkspaceAckWire::from(ack))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}
