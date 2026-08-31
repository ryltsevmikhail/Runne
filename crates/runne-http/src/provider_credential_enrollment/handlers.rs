#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected V2 router remains unmounted until qualified admission is composed"
    )
)]

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    response::{IntoResponse, Response},
};
use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentHostError,
    ProviderCredentialEnrollmentHostPort, ProviderCredentialProviderV2, VerifyProviderCredential,
};
use runne_application::local_session::AuthenticatedRuntimeSession;

use super::{
    ProviderCredentialEnrollmentHttpAdmission, ProviderCredentialEnrollmentHttpState,
    wire::ResumeBody,
};
use crate::error::{RequestId, canonical_error_response};

pub(super) async fn begin<H>(
    State(state): State<ProviderCredentialEnrollmentHttpState<H>>,
    admission: Option<Extension<Arc<ProviderCredentialEnrollmentHttpAdmission>>>,
    session: Option<Extension<AuthenticatedRuntimeSession>>,
    request_id: Option<Extension<RequestId>>,
    body: Result<Json<BeginProviderCredentialEnrollment>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    H: ProviderCredentialEnrollmentHostPort,
{
    let request_id = request_id
        .map(|value| value.0)
        .unwrap_or_else(RequestId::generate);
    let Json(command) = match body {
        Ok(value) => value,
        Err(_) => return invalid(&request_id),
    };
    let admission = match mutation_admission_for_begin(&state, admission, session, &command) {
        Ok(value) => value,
        Err(error) => return host_error(error, &request_id),
    };
    let (authority, proof, context) = match admission.take_mutation() {
        Ok(value) => value,
        Err(error) => return host_error(error, &request_id),
    };
    match state.host.begin(authority, proof, context, command).await {
        Ok(snapshot) => (axum::http::StatusCode::ACCEPTED, Json(snapshot)).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

pub(super) async fn resume<H>(
    State(state): State<ProviderCredentialEnrollmentHttpState<H>>,
    admission: Option<Extension<Arc<ProviderCredentialEnrollmentHttpAdmission>>>,
    request_id: Option<Extension<RequestId>>,
    body: Result<Json<ResumeBody>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    H: ProviderCredentialEnrollmentHostPort,
{
    let request_id = request_id
        .map(|value| value.0)
        .unwrap_or_else(RequestId::generate);
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => return invalid(&request_id),
    };
    let Some(Extension(admission)) = admission else {
        return host_error(
            ProviderCredentialEnrollmentHostError::AccessDenied,
            &request_id,
        );
    };
    let (authority, context) = match admission.take_base() {
        Ok(value) => value,
        Err(error) => return host_error(error, &request_id),
    };
    match state
        .host
        .resume(authority, context, body.operation_id)
        .await
    {
        Ok(snapshot) => (axum::http::StatusCode::OK, Json(snapshot)).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

fn mutation_admission_for_begin<H>(
    state: &ProviderCredentialEnrollmentHttpState<H>,
    admission: Option<Extension<Arc<ProviderCredentialEnrollmentHttpAdmission>>>,
    session: Option<Extension<AuthenticatedRuntimeSession>>,
    command: &BeginProviderCredentialEnrollment,
) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError> {
    resolve_mutation(state, admission, session, |resolver, session_id| {
        resolver.resolve_begin(session_id, command)
    })
}

fn mutation_admission_for_verify<H>(
    state: &ProviderCredentialEnrollmentHttpState<H>,
    admission: Option<Extension<Arc<ProviderCredentialEnrollmentHttpAdmission>>>,
    session: Option<Extension<AuthenticatedRuntimeSession>>,
    command: &VerifyProviderCredential,
) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError> {
    resolve_mutation(state, admission, session, |resolver, session_id| {
        resolver.resolve_verify(session_id, command)
    })
}

fn resolve_mutation<H>(
    state: &ProviderCredentialEnrollmentHttpState<H>,
    admission: Option<Extension<Arc<ProviderCredentialEnrollmentHttpAdmission>>>,
    session: Option<Extension<AuthenticatedRuntimeSession>>,
    resolve: impl FnOnce(
        &dyn super::ProviderCredentialEnrollmentHttpAdmissionResolver,
        [u8; 16],
    ) -> Result<
        Arc<ProviderCredentialEnrollmentHttpAdmission>,
        ProviderCredentialEnrollmentHostError,
    >,
) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError> {
    match (state.resolver.as_deref(), admission, session) {
        (Some(resolver), None, Some(Extension(session))) => {
            resolve(resolver, *session.binding.ephemeral().session_id())
        }
        (None, Some(Extension(admission)), _) => Ok(admission),
        _ => Err(ProviderCredentialEnrollmentHostError::AccessDenied),
    }
}

pub(super) async fn status<H>(
    State(state): State<ProviderCredentialEnrollmentHttpState<H>>,
    admission: Option<Extension<Arc<ProviderCredentialEnrollmentHttpAdmission>>>,
    request_id: Option<Extension<RequestId>>,
    Path(provider): Path<String>,
) -> Response
where
    H: ProviderCredentialEnrollmentHostPort,
{
    let request_id = request_id
        .map(|value| value.0)
        .unwrap_or_else(RequestId::generate);
    let provider = match provider.as_str() {
        "openai" => ProviderCredentialProviderV2::OpenAi,
        "deepseek" => ProviderCredentialProviderV2::DeepSeek,
        _ => return invalid(&request_id),
    };
    let Some(Extension(admission)) = admission else {
        return host_error(
            ProviderCredentialEnrollmentHostError::AccessDenied,
            &request_id,
        );
    };
    let (authority, _) = match admission.take_base() {
        Ok(value) => value,
        Err(error) => return host_error(error, &request_id),
    };
    match state.host.status(authority, provider).await {
        Ok(snapshot) => (axum::http::StatusCode::OK, Json(snapshot)).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

pub(super) async fn verify<H>(
    State(state): State<ProviderCredentialEnrollmentHttpState<H>>,
    admission: Option<Extension<Arc<ProviderCredentialEnrollmentHttpAdmission>>>,
    session: Option<Extension<AuthenticatedRuntimeSession>>,
    request_id: Option<Extension<RequestId>>,
    body: Result<Json<VerifyProviderCredential>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    H: ProviderCredentialEnrollmentHostPort,
{
    let request_id = request_id
        .map(|value| value.0)
        .unwrap_or_else(RequestId::generate);
    let Json(command) = match body {
        Ok(value) => value,
        Err(_) => return invalid(&request_id),
    };
    let admission = match mutation_admission_for_verify(&state, admission, session, &command) {
        Ok(value) => value,
        Err(error) => return host_error(error, &request_id),
    };
    let (authority, proof, context) = match admission.take_mutation() {
        Ok(value) => value,
        Err(error) => return host_error(error, &request_id),
    };
    match state.host.verify(authority, proof, context, command).await {
        Ok(snapshot) => (axum::http::StatusCode::ACCEPTED, Json(snapshot)).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

fn host_error(error: ProviderCredentialEnrollmentHostError, request_id: &RequestId) -> Response {
    let (status, code) = match error {
        ProviderCredentialEnrollmentHostError::InvalidRequest => (
            axum::http::StatusCode::BAD_REQUEST,
            "provider_credential_invalid_request",
        ),
        ProviderCredentialEnrollmentHostError::AccessDenied => (
            axum::http::StatusCode::FORBIDDEN,
            "provider_credential_access_denied",
        ),
        ProviderCredentialEnrollmentHostError::Conflict => (
            axum::http::StatusCode::CONFLICT,
            "provider_credential_conflict",
        ),
        ProviderCredentialEnrollmentHostError::Unsupported => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "provider_credential_unsupported",
        ),
        ProviderCredentialEnrollmentHostError::Unavailable => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "provider_credential_unavailable",
        ),
        ProviderCredentialEnrollmentHostError::InvariantViolation => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "provider_credential_invariant_violation",
        ),
    };
    canonical_error_response(status, code, request_id)
}

fn invalid(request_id: &RequestId) -> Response {
    host_error(
        ProviderCredentialEnrollmentHostError::InvalidRequest,
        request_id,
    )
}
