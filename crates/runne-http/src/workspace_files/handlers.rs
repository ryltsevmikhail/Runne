use super::{
    WorkspaceFileHttpState,
    wire::{FileContentWire, FilePageWire},
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
use runne_api::{
    WorkspaceFileHostError, WorkspaceFileHostPort, WorkspaceFileListRequest,
    WorkspaceFileQueryContext, WorkspaceFileReadRequest,
};
use runne_domain::id::WorkspaceId;

#[derive(serde::Deserialize)]
pub(super) struct FileListQuery {
    pub path: Option<String>,
    pub limit: Option<u16>,
}
#[derive(serde::Deserialize)]
pub(super) struct FileReadQuery {
    pub path: String,
}

pub(super) async fn list_files<H>(
    State(state): State<WorkspaceFileHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(workspace_id): Path<String>,
    query: Result<Query<FileListQuery>, axum::extract::rejection::QueryRejection>,
) -> Response
where
    H: WorkspaceFileHostPort,
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
            return response_error(StatusCode::BAD_REQUEST, "invalid_file_query", &request_id);
        }
    };
    let request = match WorkspaceFileListRequest::new(
        id,
        query.path.unwrap_or_default(),
        query.limit.unwrap_or(50),
    ) {
        Ok(value) => value,
        Err(error) => return host_error(error, &request_id),
    };
    match state
        .host
        .list_files(
            WorkspaceFileQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            request,
        )
        .await
    {
        Ok(page) => (StatusCode::OK, Json(FilePageWire::from(page))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

pub(super) async fn read_file<H>(
    State(state): State<WorkspaceFileHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(workspace_id): Path<String>,
    query: Result<Query<FileReadQuery>, axum::extract::rejection::QueryRejection>,
) -> Response
where
    H: WorkspaceFileHostPort,
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
            return response_error(StatusCode::BAD_REQUEST, "invalid_file_query", &request_id);
        }
    };
    let request = match WorkspaceFileReadRequest::new(id, query.path) {
        Ok(value) => value,
        Err(error) => return host_error(error, &request_id),
    };
    match state
        .host
        .read_file(
            WorkspaceFileQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            request,
        )
        .await
    {
        Ok(content) => (StatusCode::OK, Json(FileContentWire::from(content))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

fn host_error(error: WorkspaceFileHostError, request_id: &RequestId) -> Response {
    let (status, code) = match error {
        WorkspaceFileHostError::InvalidPath | WorkspaceFileHostError::InvalidLimit => {
            (StatusCode::BAD_REQUEST, "invalid_file_request")
        }
        WorkspaceFileHostError::NotFound | WorkspaceFileHostError::Forbidden => {
            (StatusCode::NOT_FOUND, "workspace_file_not_found")
        }
        WorkspaceFileHostError::SizeLimit => {
            (StatusCode::PAYLOAD_TOO_LARGE, "workspace_file_too_large")
        }
        WorkspaceFileHostError::BinaryContent => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "workspace_file_not_text",
        ),
        WorkspaceFileHostError::Conflict => (StatusCode::CONFLICT, "workspace_file_conflict"),
        WorkspaceFileHostError::Backpressure | WorkspaceFileHostError::Unavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable")
        }
        WorkspaceFileHostError::InvariantViolation => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_invariant_violation",
        ),
    };
    response_error(status, code, request_id)
}

fn response_error(status: StatusCode, code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(status, code, request_id)
}

use axum::http::StatusCode;
