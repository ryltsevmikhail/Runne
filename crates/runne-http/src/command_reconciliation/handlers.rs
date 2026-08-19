use super::{
    CommandReconciliationHttpState,
    response::{ReconciliationResponse, durable},
    wire::ReconciliationBody,
};
use crate::{
    auth::AuthenticatedPrincipal,
    error::{RequestId, canonical_error_response},
};
use axum::{
    Json,
    extract::{Extension, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use runne_api::{
    CommandReconciliationContext, CommandReconciliationHostError, CommandReconciliationHostPort,
};
use runne_domain::id::{CommandId, IdempotencyKey};

pub(super) async fn reconcile<H>(
    State(state): State<CommandReconciliationHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Json<ReconciliationBody>, JsonRejection>,
) -> Response
where
    H: CommandReconciliationHostPort + 'static,
{
    let Some(context) = context(&headers, principal) else {
        return invalid(&request_id);
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return canonical_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                &request_id,
            );
        }
        Err(_) => return invalid(&request_id),
    };
    let Some(witness) = body.witness() else {
        return invalid(&request_id);
    };
    match state.host.reconcile_command(context, witness).await {
        Ok(disposition) if disposition.is_not_committed_retryable() => {
            Json(ReconciliationResponse::NotCommittedRetryable).into_response()
        }
        Ok(disposition) if disposition.is_indeterminate() => {
            Json(ReconciliationResponse::Indeterminate).into_response()
        }
        Ok(value) => value.outcome().and_then(durable).map_or_else(
            || {
                canonical_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    CommandReconciliationHostError::InvariantViolation.code(),
                    &request_id,
                )
            },
            |outcome| {
                Json(ReconciliationResponse::DurablyRecorded {
                    outcome: Box::new(outcome),
                })
                .into_response()
            },
        ),
        Err(error) => canonical_error_response(error_status(error), error.code(), &request_id),
    }
}
fn context(
    headers: &HeaderMap,
    principal: AuthenticatedPrincipal,
) -> Option<CommandReconciliationContext> {
    let command_id = exactly_one(headers, "x-command-id")?
        .parse::<CommandId>()
        .ok()?;
    let idempotency_key =
        IdempotencyKey::new(exactly_one(headers, "idempotency-key")?.to_owned()).ok()?;
    Some(CommandReconciliationContext::new(
        command_id,
        idempotency_key,
        principal.as_api_principal().clone(),
    ))
}
fn exactly_one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}
fn invalid(request_id: &RequestId) -> Response {
    canonical_error_response(StatusCode::BAD_REQUEST, "invalid_request", request_id)
}
const fn error_status(error: CommandReconciliationHostError) -> StatusCode {
    match error {
        CommandReconciliationHostError::Conflict => StatusCode::CONFLICT,
        CommandReconciliationHostError::Backpressure
        | CommandReconciliationHostError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        CommandReconciliationHostError::InvariantViolation => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
