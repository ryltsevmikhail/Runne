use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    response::{IntoResponse, Response},
};
use gocode_api::{
    ProjectQueryContext, ProjectWorkspaceCommandHostPort, ProjectWorkspacePageSize,
    ProjectWorkspaceQueryHostPort,
};
use gocode_domain::id::{ProjectId, WorkspaceId};

use super::helpers::{bad_request, host_error, not_found};
use crate::{
    auth::AuthenticatedPrincipal,
    error::RequestId,
    project_workspace::{ProjectWorkspaceHttpState, wire::*},
};
const DEFAULT_PAGE_LIMIT: u16 = 50;
pub(crate) async fn list_projects<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    let query = match query {
        Ok(Query(value)) => value,
        Err(_) => return bad_request("invalid_page", &request_id),
    };
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if ProjectWorkspacePageSize::new(limit).is_err() {
        return bad_request("invalid_page", &request_id);
    }
    let request = match gocode_api::ProjectPageRequest::from_token(limit, query.cursor.as_deref()) {
        Ok(value) => value,
        Err(_) => return not_found(&request_id),
    };
    match state
        .host
        .list_projects(
            ProjectQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            request,
        )
        .await
    {
        Ok(page) => (
            axum::http::StatusCode::OK,
            Json(ProjectPageWire::from(page)),
        )
            .into_response(),
        Err(error) => host_error(error, &request_id),
    }
}
pub(crate) async fn get_project<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(project_id): Path<String>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    let id = match project_id.parse::<ProjectId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_project_id", &request_id),
    };
    match state
        .host
        .get_project(
            ProjectQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            id,
        )
        .await
    {
        Ok(snapshot) => (
            axum::http::StatusCode::OK,
            Json(ProjectWire::from(snapshot)),
        )
            .into_response(),
        Err(error) => host_error(error, &request_id),
    }
}
pub(crate) async fn list_workspaces<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(project_id): Path<String>,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    let id = match project_id.parse::<ProjectId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_project_id", &request_id),
    };
    let query = match query {
        Ok(Query(value)) => value,
        Err(_) => return bad_request("invalid_page", &request_id),
    };
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if ProjectWorkspacePageSize::new(limit).is_err() {
        return bad_request("invalid_page", &request_id);
    }
    let request = match gocode_api::WorkspacePageRequest::from_token(limit, query.cursor.as_deref())
    {
        Ok(value) => value,
        Err(_) => return not_found(&request_id),
    };
    match state
        .host
        .list_workspaces(
            ProjectQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            id,
            request,
        )
        .await
    {
        Ok(page) => (
            axum::http::StatusCode::OK,
            Json(WorkspacePageWire::from(page)),
        )
            .into_response(),
        Err(error) => host_error(error, &request_id),
    }
}
pub(crate) async fn get_workspace<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(workspace_id): Path<String>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    let id = match workspace_id.parse::<WorkspaceId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_workspace_id", &request_id),
    };
    match state
        .host
        .get_workspace(
            ProjectQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            id,
        )
        .await
    {
        Ok(snapshot) => (
            axum::http::StatusCode::OK,
            Json(WorkspaceWire::from(snapshot)),
        )
            .into_response(),
        Err(error) => host_error(error, &request_id),
    }
}
