use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use runne_api::{
    ProjectTrustControlError, ProjectTrustControlHostPort, ProjectTrustControlRequest,
    ProjectTrustDecision,
};
use runne_domain::id::{ProjectId, WorkspaceId};

use super::{
    ProjectTrustControlHttpState,
    wire::{DecisionBody, SnapshotWire},
};
use crate::{
    auth::AuthenticatedPrincipal,
    error::{RequestId, canonical_error_response},
};

pub(super) async fn get_snapshot<H: ProjectTrustControlHostPort + 'static>(
    State(state): State<ProjectTrustControlHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path((project, workspace)): Path<(String, String)>,
) -> Response {
    let (Ok(project), Ok(workspace)) = (
        project.parse::<ProjectId>(),
        workspace.parse::<WorkspaceId>(),
    ) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_trust_binding",
            &request_id,
        );
    };
    match state
        .0
        .get_project_trust(principal.as_api_principal().clone(), project, workspace)
        .await
    {
        Ok(snapshot) => no_store(Json(SnapshotWire::from(snapshot)).into_response()),
        Err(e) => map_error(e, &request_id),
    }
}

pub(super) async fn decide<H: ProjectTrustControlHostPort + 'static>(
    State(state): State<ProjectTrustControlHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path((project, workspace)): Path<(String, String)>,
    body: Result<Json<DecisionBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let (Ok(project), Ok(workspace), Ok(Json(body))) = (
        project.parse::<ProjectId>(),
        workspace.parse::<WorkspaceId>(),
        body,
    ) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_trust_request",
            &request_id,
        );
    };
    let decision = match body.action.as_str() {
        "confirm_project" => ProjectTrustDecision::ConfirmProject,
        "revoke_project" => ProjectTrustDecision::RevokeProject,
        _ => return error(StatusCode::BAD_REQUEST, "invalid_trust_action", &request_id),
    };
    let parse = parse_decimal;
    let (Some(epoch), Some(revision), Some(project_version), Some(workspace_version)) = (
        parse(&body.expected_epoch),
        parse(&body.expected_revision),
        parse(&body.expected_project_version),
        parse(&body.expected_workspace_version),
    ) else {
        return error(StatusCode::BAD_REQUEST, "invalid_trust_token", &request_id);
    };
    if epoch == 0 || project_version == 0 || workspace_version == 0 {
        return error(StatusCode::BAD_REQUEST, "invalid_trust_token", &request_id);
    }
    let root_version = match body.expected_root_admission_version.as_deref() {
        Some(value) => match parse(value) {
            Some(v) => Some(v),
            None => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_trust_binding",
                    &request_id,
                );
            }
        },
        None => None,
    };
    if root_version.is_some_and(|version| version == 0)
        || (decision == ProjectTrustDecision::RevokeProject && root_version.is_some())
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_trust_binding",
            &request_id,
        );
    }
    let request = ProjectTrustControlRequest {
        decision,
        expected_epoch: epoch,
        expected_revision: revision,
        expected_project_version: project_version,
        expected_workspace_version: workspace_version,
        expected_root_admission_version: root_version,
    };
    match state
        .0
        .decide_project_trust(
            principal.as_api_principal().clone(),
            project,
            workspace,
            request,
        )
        .await
    {
        Ok(snapshot) => no_store(Json(SnapshotWire::from(snapshot)).into_response()),
        Err(e) => map_error(e, &request_id),
    }
}

fn parse_decimal(value: &str) -> Option<u64> {
    let parsed = value.parse::<u64>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn map_error(value: ProjectTrustControlError, request: &RequestId) -> Response {
    let (status, code) = match value {
        ProjectTrustControlError::NotFound => {
            (StatusCode::NOT_FOUND, "project_workspace_not_found")
        }
        ProjectTrustControlError::Conflict => (StatusCode::CONFLICT, "trust_control_conflict"),
        ProjectTrustControlError::ManagedPolicy => (StatusCode::FORBIDDEN, "managed_trust_policy"),
        ProjectTrustControlError::RootUnavailable => {
            (StatusCode::CONFLICT, "trust_root_unavailable")
        }
        ProjectTrustControlError::Unavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, "trust_control_unavailable")
        }
    };
    error(status, code, request)
}

fn error(status: StatusCode, code: &'static str, request: &RequestId) -> Response {
    no_store(canonical_error_response(status, code, request))
}

fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::parse_decimal;

    #[test]
    fn trust_wire_numbers_require_canonical_decimal_strings() {
        for accepted in ["0", "1", "18446744073709551615"] {
            assert!(parse_decimal(accepted).is_some());
        }
        for rejected in ["", "+1", "01", " 1", "-1", "18446744073709551616"] {
            assert!(parse_decimal(rejected).is_none());
        }
    }
}
