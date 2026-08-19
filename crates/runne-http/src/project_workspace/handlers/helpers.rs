use axum::{
    extract::rejection::JsonRejection,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use runne_api::{ApiActor, ProjectCommandContext, ProjectWorkspaceHostError};
use runne_domain::id::{CommandId, IdempotencyKey};

use crate::{
    auth::AuthenticatedPrincipal,
    error::{RequestId, canonical_error_response},
};

pub(super) fn context(
    headers: &HeaderMap,
    principal: &AuthenticatedPrincipal,
    actor: &ApiActor,
) -> Result<ProjectCommandContext, &'static str> {
    let command_id = header(headers, "x-command-id")
        .and_then(|value| value.parse::<CommandId>().ok())
        .ok_or("invalid_command_id")?;
    let idempotency_key = header(headers, "idempotency-key")
        .and_then(|value| IdempotencyKey::new(value).ok())
        .ok_or("invalid_idempotency_key")?;
    Ok(ProjectCommandContext {
        command_id,
        idempotency_key,
        principal: principal.as_api_principal().clone(),
        actor: actor.clone(),
    })
}
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    values
        .next()
        .is_none()
        .then(|| value.to_str().ok())
        .flatten()
}
pub(super) fn host_error(error: ProjectWorkspaceHostError, request_id: &RequestId) -> Response {
    let (status, code) = match error {
        ProjectWorkspaceHostError::NotFound | ProjectWorkspaceHostError::Forbidden => {
            (StatusCode::NOT_FOUND, "project_workspace_not_found")
        }
        ProjectWorkspaceHostError::Conflict => (StatusCode::CONFLICT, "project_workspace_conflict"),
        ProjectWorkspaceHostError::Backpressure => {
            (StatusCode::SERVICE_UNAVAILABLE, "runtime_backpressure")
        }
        ProjectWorkspaceHostError::Unavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable")
        }
        ProjectWorkspaceHostError::InvariantViolation => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_invariant_violation",
        ),
    };
    canonical_error_response(status, code, request_id)
}
pub(super) fn bad_request(code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(StatusCode::BAD_REQUEST, code, request_id)
}
pub(super) fn json_rejection(rejection: JsonRejection, request_id: &RequestId) -> Response {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        canonical_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            request_id,
        )
    } else {
        bad_request("invalid_request", request_id)
    }
}
pub(super) fn not_found(request_id: &RequestId) -> Response {
    canonical_error_response(
        StatusCode::NOT_FOUND,
        "project_workspace_not_found",
        request_id,
    )
}
