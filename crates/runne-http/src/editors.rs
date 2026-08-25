//! Authenticated runtime-owned scoped editor activation.

use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use runne_api::{
    ApiActor, EditorLaunchTargetV1, OpenEditorRequest, ProcessCommandContext,
    WorkspaceEditorHostError, WorkspaceEditorHostPort, WorkspaceId,
};
use runne_domain::id::{CommandId, IdempotencyKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    auth::AuthenticatedPrincipal,
    error::{RequestId, canonical_error_response},
};

/// Shared editor host and bounded daemon actor identity.
pub struct WorkspaceEditorHttpState<H> {
    pub(super) host: Arc<H>,
    pub(super) actor: ApiActor,
}

impl<H> Clone for WorkspaceEditorHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            actor: self.actor.clone(),
        }
    }
}

impl<H> WorkspaceEditorHttpState<H> {
    /// Creates an authenticated editor state.
    #[must_use]
    pub fn new(host: H, actor: ApiActor) -> Self {
        Self {
            host: Arc::new(host),
            actor,
        }
    }
}

/// Builds the scoped editor activation route.
pub fn workspace_editor_router<H>(state: WorkspaceEditorHttpState<H>) -> Router
where
    H: WorkspaceEditorHostPort + 'static,
{
    Router::new()
        .route(
            "/v1/workspaces/{workspace_id}/editor",
            post(open_editor::<H>),
        )
        .with_state(state)
}

async fn open_editor<H>(
    State(state): State<WorkspaceEditorHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    body: Result<Json<OpenBody>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    H: WorkspaceEditorHostPort,
{
    let workspace_id = match workspace_id.parse::<WorkspaceId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_workspace_id", &request_id),
    };
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let target = match body.target.as_str() {
        "system_default" => EditorLaunchTargetV1::SystemDefault,
        _ => return bad_request("invalid_editor_target", &request_id),
    };
    let request = match OpenEditorRequest::new(workspace_id, body.relative_path, target) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_editor_path", &request_id),
    };
    match state.host.open_editor(context, request).await {
        Ok(receipt) => (
            StatusCode::ACCEPTED,
            Json(EditorReceiptWire {
                workspace_id: receipt.workspace_id().to_string(),
                target: "system_default",
            }),
        )
            .into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

fn command_context(
    headers: &HeaderMap,
    principal: &AuthenticatedPrincipal,
    actor: &ApiActor,
) -> Result<ProcessCommandContext, &'static str> {
    let command_id = exactly_one(headers, "x-command-id")
        .and_then(|value| value.parse::<CommandId>().ok())
        .ok_or("invalid_command_id")?;
    let idempotency_key = exactly_one(headers, "idempotency-key")
        .and_then(|value| IdempotencyKey::new(value).ok())
        .ok_or("invalid_idempotency_key")?;
    Ok(ProcessCommandContext {
        command_id,
        idempotency_key,
        principal: principal.as_api_principal().clone(),
        actor: actor.clone(),
    })
}

fn exactly_one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    values
        .next()
        .is_none()
        .then(|| value.to_str().ok())
        .flatten()
}

fn host_error(error: WorkspaceEditorHostError, request_id: &RequestId) -> Response {
    let (status, code) = match error {
        WorkspaceEditorHostError::InvalidPath => (StatusCode::BAD_REQUEST, "invalid_editor_path"),
        WorkspaceEditorHostError::NotFound => (StatusCode::NOT_FOUND, "workspace_file_not_found"),
        WorkspaceEditorHostError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
        WorkspaceEditorHostError::Conflict => (StatusCode::CONFLICT, "workspace_conflict"),
        WorkspaceEditorHostError::Backpressure => {
            (StatusCode::TOO_MANY_REQUESTS, "runtime_backpressure")
        }
        WorkspaceEditorHostError::Unavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, "editor_unavailable")
        }
        WorkspaceEditorHostError::InvariantViolation => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_invariant_violation",
        ),
    };
    canonical_error_response(status, code, request_id)
}

fn bad_request(code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(StatusCode::BAD_REQUEST, code, request_id)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpenBody {
    relative_path: String,
    target: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EditorReceiptWire {
    workspace_id: String,
    target: &'static str,
}
