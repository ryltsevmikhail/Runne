//! Authenticated provider credential mutation routes.

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::put,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use runne_api::{
    ApiActor, ProviderCredentialCommandContext, ProviderCredentialControlHostPort,
    ProviderCredentialHostError, ProviderCredentialMutationAckV1, ProviderCredentialPairCommand,
    ProviderCredentialProviderV1, ProviderCredentialRevokeCommand,
};
use runne_domain::id::{CommandId, IdempotencyKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    auth::AuthenticatedPrincipal,
    error::{RequestId, canonical_error_response},
};

const MAX_BODY_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct ProviderCredentialHttpState {
    pub(super) host: Arc<dyn ProviderCredentialControlHostPort>,
    pub(super) actor: ApiActor,
}

impl ProviderCredentialHttpState {
    #[must_use]
    pub fn new(host: Arc<dyn ProviderCredentialControlHostPort>, actor: ApiActor) -> Self {
        Self { host, actor }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairBody {
    credential: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AckWire {
    provider_id: &'static str,
    status: &'static str,
}

pub fn provider_credential_router(state: ProviderCredentialHttpState) -> Router {
    Router::new()
        .route(
            "/v1/providers/{provider}/credential",
            put(pair).delete(revoke),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn pair(
    State(state): State<ProviderCredentialHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Result<Json<PairBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    let provider = match ProviderCredentialProviderV1::parse(&provider) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_provider", &request_id),
    };
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let material = match URL_SAFE_NO_PAD.decode(body.credential.as_bytes()) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_provider_credential", &request_id),
    };
    let command = match ProviderCredentialPairCommand::new(provider, material) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_provider_credential", &request_id),
    };
    match state.host.pair_provider_credential(context, command).await {
        Ok(ack) => accepted(ack),
        Err(error) => host_error(error, &request_id),
    }
}

async fn revoke(
    State(state): State<ProviderCredentialHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(provider): Path<String>,
    headers: HeaderMap,
) -> Response {
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    let provider = match ProviderCredentialProviderV1::parse(&provider) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_provider", &request_id),
    };
    match state
        .host
        .revoke_provider_credential(context, ProviderCredentialRevokeCommand::new(provider))
        .await
    {
        Ok(ack) => accepted(ack),
        Err(error) => host_error(error, &request_id),
    }
}

fn command_context(
    headers: &HeaderMap,
    principal: &AuthenticatedPrincipal,
    actor: &ApiActor,
) -> Result<ProviderCredentialCommandContext, &'static str> {
    let command_id = exactly_one(headers, "x-command-id")
        .and_then(|value| value.parse::<CommandId>().ok())
        .ok_or("invalid_command_id")?;
    let idempotency_key = exactly_one(headers, "idempotency-key")
        .and_then(|value| IdempotencyKey::new(value).ok())
        .ok_or("invalid_idempotency_key")?;
    Ok(ProviderCredentialCommandContext {
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

fn accepted(ack: ProviderCredentialMutationAckV1) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(AckWire {
            provider_id: ack.provider().as_str(),
            status: credential_status(ack.status()),
        }),
    )
        .into_response()
}

fn credential_status(status: runne_api::ProviderCredentialStatusV1) -> &'static str {
    match status {
        runne_api::ProviderCredentialStatusV1::Configured => "configured",
        runne_api::ProviderCredentialStatusV1::Missing => "missing",
        runne_api::ProviderCredentialStatusV1::Unsupported => "unsupported",
        runne_api::ProviderCredentialStatusV1::AccessDenied => "access_denied",
        runne_api::ProviderCredentialStatusV1::IdentityMismatch => "identity_mismatch",
        runne_api::ProviderCredentialStatusV1::Unavailable => "unavailable",
    }
}

fn host_error(error: ProviderCredentialHostError, request_id: &RequestId) -> Response {
    let (status, code) = match error {
        ProviderCredentialHostError::InvalidRequest => {
            (StatusCode::BAD_REQUEST, "invalid_provider_credential")
        }
        ProviderCredentialHostError::Forbidden => {
            (StatusCode::FORBIDDEN, "provider_credential_forbidden")
        }
        ProviderCredentialHostError::Conflict => {
            (StatusCode::CONFLICT, "provider_credential_conflict")
        }
        ProviderCredentialHostError::Unsupported => (
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_credential_unsupported",
        ),
        ProviderCredentialHostError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_credential_unavailable",
        ),
        ProviderCredentialHostError::InvariantViolation => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_invariant_violation",
        ),
    };
    canonical_error_response(status, code, request_id)
}

fn bad_request(code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(StatusCode::BAD_REQUEST, code, request_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_wire_is_closed_and_redacted() {
        assert_eq!(
            credential_status(runne_api::ProviderCredentialStatusV1::Configured),
            "configured"
        );
        assert_eq!(
            credential_status(runne_api::ProviderCredentialStatusV1::IdentityMismatch),
            "identity_mismatch"
        );
    }

    #[test]
    fn duplicate_header_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            "x-command-id",
            "018f2e3a-7000-7000-8000-000000000003".parse().unwrap(),
        );
        headers.append(
            "x-command-id",
            "018f2e3a-7000-7000-8000-000000000004".parse().unwrap(),
        );
        assert!(exactly_one(&headers, "x-command-id").is_none());
    }
}
