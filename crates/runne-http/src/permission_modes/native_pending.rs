use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State, rejection::QueryRejection},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use runne_api::{PermissionModeHostErrorV1, PermissionModeNativePendingHostV2};
use runne_domain::id::CommandId;
use serde::Deserialize;

use crate::{auth::AuthenticatedPrincipal, error::RequestId};

struct NativePendingHttpState<H>(Arc<H>);

impl<H> Clone for NativePendingHttpState<H> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativePendingQuery {
    after: Option<String>,
}

pub(super) fn router<H: PermissionModeNativePendingHostV2 + 'static>(host: H) -> Router {
    Router::new()
        .route("/v2/permission-mode/native-pending", get(read::<H>))
        .with_state(NativePendingHttpState(Arc::new(host)))
        .layer(middleware::from_fn(super::error::no_store_middleware))
}

async fn read<H: PermissionModeNativePendingHostV2 + 'static>(
    State(state): State<NativePendingHttpState<H>>,
    axum::Extension(principal): axum::Extension<AuthenticatedPrincipal>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    query: Result<Query<NativePendingQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_permission_mode_request",
            &request_id,
        );
    };
    let after = match query.after {
        Some(value) => match value.parse::<CommandId>() {
            Ok(command) => Some(command),
            Err(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_permission_mode_request",
                    &request_id,
                );
            }
        },
        None => None,
    };
    match state
        .0
        .native_pending(principal.as_api_principal().clone(), after)
        .await
    {
        Ok(page) => Json(page).into_response(),
        Err(failure) => host_error(failure, &request_id),
    }
}

fn host_error(failure: PermissionModeHostErrorV1, request_id: &RequestId) -> Response {
    let status = match failure {
        PermissionModeHostErrorV1::NotFound => StatusCode::NOT_FOUND,
        PermissionModeHostErrorV1::PolicyDenied => StatusCode::FORBIDDEN,
        PermissionModeHostErrorV1::Conflict
        | PermissionModeHostErrorV1::IdempotencyConflict
        | PermissionModeHostErrorV1::StaleRevision
        | PermissionModeHostErrorV1::Expired
        | PermissionModeHostErrorV1::Cancelled
        | PermissionModeHostErrorV1::ReconciliationRequired => StatusCode::CONFLICT,
        PermissionModeHostErrorV1::NativeAuthorityUnavailable
        | PermissionModeHostErrorV1::EnforcementUnavailable
        | PermissionModeHostErrorV1::CompositePolicyUnenforceable
        | PermissionModeHostErrorV1::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        PermissionModeHostErrorV1::UnsupportedPresetVersion
        | PermissionModeHostErrorV1::InvariantViolation => StatusCode::BAD_REQUEST,
    };
    error(status, failure.code(), request_id)
}

fn error(status: StatusCode, code: &'static str, request_id: &RequestId) -> Response {
    crate::error::canonical_error_response(status, code, request_id)
}
