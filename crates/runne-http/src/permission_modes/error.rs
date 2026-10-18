use axum::{
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL},
    middleware::Next,
    response::Response,
};
use runne_api::PermissionModeHostErrorV1;

use crate::error::{RequestId, canonical_error_response};

pub(super) fn invalid_request(request_id: &RequestId) -> Response {
    response(
        StatusCode::BAD_REQUEST,
        "invalid_permission_mode_request",
        request_id,
    )
}

pub(super) fn response_mismatch(request_id: &RequestId) -> Response {
    response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "permission_mode_response_mismatch",
        request_id,
    )
}

pub(super) fn host_error(error: PermissionModeHostErrorV1, request_id: &RequestId) -> Response {
    let status = match error {
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
    response(status, error.code(), request_id)
}

fn response(status: StatusCode, code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(status, code, request_id)
}

pub(super) async fn no_store_middleware(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
