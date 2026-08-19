use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use runne_api::{
    ExistingProjectCommand, ProjectWorkspaceCommandHostPort, ProjectWorkspaceDisplayNameInput,
    ProjectWorkspaceQueryHostPort,
};
use runne_domain::id::ProjectId;

use super::helpers::{bad_request, context, host_error, json_rejection};
use crate::{
    auth::AuthenticatedPrincipal,
    error::RequestId,
    project_workspace::{ProjectWorkspaceHttpState, wire::*},
};
pub(crate) async fn create_project<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Json<CreateProjectBody>, JsonRejection>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    let context = match context(&headers, &principal, &state.actor) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    let Json(body) = match body {
        Ok(value) => value,
        Err(error) => return json_rejection(error, &request_id),
    };
    let project_id = match body.project_id.parse() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_project_id", &request_id),
    };
    let display_name = match ProjectWorkspaceDisplayNameInput::new(body.display_name) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_display_name", &request_id),
    };
    match state
        .host
        .create_project(
            context,
            runne_api::CreateProjectCommand {
                project_id,
                display_name,
            },
        )
        .await
    {
        Ok(ack) => (StatusCode::ACCEPTED, Json(ProjectAckWire::from(ack))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}
pub(crate) async fn archive_project<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ExistingBody>, JsonRejection>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    mutate(state, principal, request_id, project_id, headers, body, 0).await
}
pub(crate) async fn restore_project<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ExistingBody>, JsonRejection>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    mutate(state, principal, request_id, project_id, headers, body, 1).await
}
pub(crate) async fn delete_project<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ExistingBody>, JsonRejection>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    mutate(state, principal, request_id, project_id, headers, body, 2).await
}
async fn mutate<H>(
    state: ProjectWorkspaceHttpState<H>,
    principal: AuthenticatedPrincipal,
    request_id: RequestId,
    project_id: String,
    headers: HeaderMap,
    body: Result<Json<ExistingBody>, JsonRejection>,
    operation: u8,
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
        Err(error) => return json_rejection(error, &request_id),
    };
    if body.expected_version == 0 {
        return bad_request("invalid_expected_version", &request_id);
    }
    let command = ExistingProjectCommand {
        project_id,
        expected_version: body.expected_version,
    };
    let result = match operation {
        0 => state.host.archive_project(context, command).await,
        1 => state.host.restore_project(context, command).await,
        _ => state.host.delete_project(context, command).await,
    };
    match result {
        Ok(ack) => (StatusCode::ACCEPTED, Json(ProjectAckWire::from(ack))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}
