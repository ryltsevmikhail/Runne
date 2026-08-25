use super::{
    ApprovalHttpState,
    wire::{ApprovalListWire, ApprovalSummaryWire, DecisionAckWire, DecisionBody},
};
use crate::{
    auth::AuthenticatedPrincipal,
    error::{RequestId, canonical_error_response},
};
use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use runne_api::{
    ApiActor, ApprovalCommandContext, ApprovalCommandHostPort, ApprovalDecision,
    ApprovalDecisionCommand, ApprovalHostError, ApprovalQueryContext, ApprovalQueryHostPort,
};
use runne_domain::id::{ApprovalId, CommandId, IdempotencyKey};

pub(super) async fn list_pending<H>(
    State(state): State<ApprovalHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
) -> Response
where
    H: ApprovalQueryHostPort,
{
    match state
        .host
        .list_pending_approvals(ApprovalQueryContext {
            principal: principal.as_api_principal().clone(),
        })
        .await
    {
        Ok(items) => (
            StatusCode::OK,
            Json(ApprovalListWire {
                items: items.into_iter().map(ApprovalSummaryWire::from).collect(),
            }),
        )
            .into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

pub(super) async fn get_approval<H>(
    State(state): State<ApprovalHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(approval_id): Path<String>,
) -> Response
where
    H: ApprovalQueryHostPort,
{
    let approval_id = match approval_id.parse::<ApprovalId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_approval_id", &request_id),
    };
    match state
        .host
        .get_approval(
            ApprovalQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            approval_id,
        )
        .await
    {
        Ok(value) => (StatusCode::OK, Json(ApprovalSummaryWire::from(value))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

pub(super) async fn decide<H>(
    State(state): State<ApprovalHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(approval_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<DecisionBody>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    H: ApprovalCommandHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    let approval_id = match approval_id.parse::<ApprovalId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_approval_id", &request_id),
    };
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let decision = match body.decision.as_str() {
        "approve" => ApprovalDecision::Approve,
        "deny" => ApprovalDecision::Deny,
        _ => return bad_request("invalid_approval_decision", &request_id),
    };
    let digest = match parse_digest(&body.action_digest) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_action_digest", &request_id),
    };
    let command = match ApprovalDecisionCommand::new(
        approval_id,
        body.expected_version,
        decision,
        digest,
        body.policy_revision,
        body.renderer_generation,
    ) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_approval_command", &request_id),
    };
    match state.host.decide_approval(context, command).await {
        Ok(value) => (StatusCode::ACCEPTED, Json(DecisionAckWire::from(value))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

fn command_context(
    headers: &HeaderMap,
    principal: &AuthenticatedPrincipal,
    actor: &ApiActor,
) -> Result<ApprovalCommandContext, &'static str> {
    let command_id = exactly_one(headers, "x-command-id")
        .and_then(|value| value.parse::<CommandId>().ok())
        .ok_or("invalid_command_id")?;
    let idempotency_key = exactly_one(headers, "idempotency-key")
        .and_then(|value| IdempotencyKey::new(value).ok())
        .ok_or("invalid_idempotency_key")?;
    Ok(ApprovalCommandContext {
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

fn parse_digest(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64 || value != value.to_ascii_lowercase() {
        return Err(());
    }
    hex::decode(value)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

fn host_error(error: ApprovalHostError, request_id: &RequestId) -> Response {
    let (status, code) = match error {
        ApprovalHostError::NotFound => (StatusCode::NOT_FOUND, "approval_not_found"),
        ApprovalHostError::Conflict => (StatusCode::CONFLICT, "approval_conflict"),
        ApprovalHostError::Forbidden => (StatusCode::FORBIDDEN, "approval_forbidden"),
        ApprovalHostError::Expired => (StatusCode::CONFLICT, "approval_expired"),
        ApprovalHostError::Backpressure => (StatusCode::TOO_MANY_REQUESTS, "runtime_backpressure"),
        ApprovalHostError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable"),
        ApprovalHostError::InvariantViolation => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_invariant_violation",
        ),
    };
    canonical_error_response(status, code, request_id)
}

fn bad_request(code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(StatusCode::BAD_REQUEST, code, request_id)
}
