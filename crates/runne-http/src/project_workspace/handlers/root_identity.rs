use super::helpers::{bad_request, host_error};
use crate::{
    auth::AuthenticatedPrincipal,
    error::RequestId,
    project_workspace::{ProjectWorkspaceHttpState, wire::WorkspaceWire},
};
use axum::{
    Json,
    extract::{Extension, Path, State},
    response::{IntoResponse, Response},
};
use runne_api::{
    ProjectQueryContext, ProjectWorkspaceCommandHostPort, ProjectWorkspaceQueryHostPort,
};

pub(crate) async fn find_workspace_by_root<H>(
    State(state): State<ProjectWorkspaceHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(encoded): Path<String>,
) -> Response
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort,
{
    let digest = match hex::decode(&encoded)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    {
        Some(digest) if digest != [0; 32] && hex::encode(digest) == encoded => digest,
        _ => return bad_request("invalid_root_identity", &request_id),
    };
    match state
        .host
        .find_workspace_by_root(
            ProjectQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            digest,
        )
        .await
    {
        Ok(workspace) => (
            axum::http::StatusCode::OK,
            Json(workspace.map(WorkspaceWire::from)),
        )
            .into_response(),
        Err(error) => host_error(error, &request_id),
    }
}
