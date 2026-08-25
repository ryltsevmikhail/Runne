use super::{
    WorkspaceDiffHttpState,
    wire::{ChangeSetWire, DiffWire},
};
use crate::{
    auth::AuthenticatedPrincipal,
    error::{RequestId, canonical_error_response},
};
use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    response::{IntoResponse, Response},
};
use http::StatusCode;
use runne_api::{
    WorkspaceChangeListRequest, WorkspaceDiffHostError, WorkspaceDiffHostPort,
    WorkspaceDiffQueryContext, WorkspaceDiffReadRequest,
};
use runne_domain::id::WorkspaceId;

#[derive(serde::Deserialize)]
pub(super) struct ChangeListQuery {
    pub limit: Option<u16>,
}
#[derive(serde::Deserialize)]
pub(super) struct DiffQuery {
    pub path: String,
}

pub(super) async fn list_changes<H>(
    State(state): State<WorkspaceDiffHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(workspace_id): Path<String>,
    query: Result<Query<ChangeListQuery>, axum::extract::rejection::QueryRejection>,
) -> Response
where
    H: WorkspaceDiffHostPort,
{
    let id = match workspace_id.parse::<WorkspaceId>() {
        Ok(value) => value,
        Err(_) => {
            return response_error(StatusCode::BAD_REQUEST, "invalid_workspace_id", &request_id);
        }
    };
    let Query(query) = match query {
        Ok(value) => value,
        Err(_) => {
            return response_error(StatusCode::BAD_REQUEST, "invalid_change_query", &request_id);
        }
    };
    let request = match WorkspaceChangeListRequest::new(id, query.limit.unwrap_or(50)) {
        Ok(value) => value,
        Err(error) => return host_error(error, &request_id),
    };
    match state
        .host
        .list_changes(
            WorkspaceDiffQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            request,
        )
        .await
    {
        Ok(value) => (StatusCode::OK, Json(ChangeSetWire::from(value))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

pub(super) async fn read_diff<H>(
    State(state): State<WorkspaceDiffHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(workspace_id): Path<String>,
    query: Result<Query<DiffQuery>, axum::extract::rejection::QueryRejection>,
) -> Response
where
    H: WorkspaceDiffHostPort,
{
    let id = match workspace_id.parse::<WorkspaceId>() {
        Ok(value) => value,
        Err(_) => {
            return response_error(StatusCode::BAD_REQUEST, "invalid_workspace_id", &request_id);
        }
    };
    let Query(query) = match query {
        Ok(value) => value,
        Err(_) => {
            return response_error(StatusCode::BAD_REQUEST, "invalid_diff_query", &request_id);
        }
    };
    let request = match WorkspaceDiffReadRequest::new(id, query.path) {
        Ok(value) => value,
        Err(error) => return host_error(error, &request_id),
    };
    match state
        .host
        .read_diff(
            WorkspaceDiffQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            request,
        )
        .await
    {
        Ok(value) => (StatusCode::OK, Json(DiffWire::from(value))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

fn host_error(error: WorkspaceDiffHostError, request_id: &RequestId) -> Response {
    let (status, code) = match error {
        WorkspaceDiffHostError::InvalidPath | WorkspaceDiffHostError::InvalidLimit => {
            (StatusCode::BAD_REQUEST, "invalid_diff_request")
        }
        WorkspaceDiffHostError::NotFound | WorkspaceDiffHostError::Forbidden => {
            (StatusCode::NOT_FOUND, "workspace_diff_not_found")
        }
        WorkspaceDiffHostError::SizeLimit => {
            (StatusCode::PAYLOAD_TOO_LARGE, "workspace_diff_too_large")
        }
        WorkspaceDiffHostError::BinaryContent => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "workspace_diff_not_text",
        ),
        WorkspaceDiffHostError::Conflict => (StatusCode::CONFLICT, "workspace_diff_conflict"),
        WorkspaceDiffHostError::Backpressure | WorkspaceDiffHostError::Unavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable")
        }
        WorkspaceDiffHostError::InvariantViolation => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_invariant_violation",
        ),
    };
    response_error(status, code, request_id)
}

fn response_error(status: StatusCode, code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(status, code, request_id)
}
