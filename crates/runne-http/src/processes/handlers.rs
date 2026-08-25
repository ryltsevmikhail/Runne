use super::{
    ProcessHttpState,
    wire::{OutputChunkWire, OutputPageWire, OutputQuery, SnapshotWire, StartBody, StopBody},
};
use crate::{
    auth::AuthenticatedPrincipal,
    error::{RequestId, canonical_error_response},
};
use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use runne_api::{
    ApiActor, ExistingProcessCommand, ProcessCommandContext, ProcessHostError, ProcessHostPort,
    ProcessOutputStream, ProcessSnapshot, StartProcessCommand,
};
use runne_domain::id::{CommandId, IdempotencyKey, ProcessId};

pub(super) async fn start_process<H>(
    State(state): State<ProcessHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Json<StartBody>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    H: ProcessHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let command = match parse_start(body) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    match state.host.start_process(context, command).await {
        Ok(snapshot) => (StatusCode::ACCEPTED, Json(snapshot_to_wire(snapshot))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

pub(super) async fn get_process<H>(
    State(state): State<ProcessHttpState<H>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Extension(request_id): Extension<RequestId>,
    Path(process_id): Path<String>,
) -> Response
where
    H: ProcessHostPort,
{
    let process_id = match process_id.parse::<ProcessId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_process_id", &request_id),
    };
    let Some(Extension(principal)) = principal else {
        return canonical_error_response(StatusCode::UNAUTHORIZED, "unauthorized", &request_id);
    };
    match state
        .host
        .get_process(
            runne_api::ProcessQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            process_id,
        )
        .await
    {
        Ok(snapshot) => Json(snapshot_to_wire(snapshot)).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

pub(super) async fn read_output<H>(
    State(state): State<ProcessHttpState<H>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Extension(request_id): Extension<RequestId>,
    Path(process_id): Path<String>,
    query: Result<Query<OutputQuery>, axum::extract::rejection::QueryRejection>,
) -> Response
where
    H: ProcessHostPort,
{
    let process_id = match process_id.parse::<ProcessId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_process_id", &request_id),
    };
    let Query(query) = match query {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_output_query", &request_id),
    };
    let Some(Extension(principal)) = principal else {
        return canonical_error_response(StatusCode::UNAUTHORIZED, "unauthorized", &request_id);
    };
    let limit = query.limit.unwrap_or(64);
    match state
        .host
        .read_process_output(
            runne_api::ProcessQueryContext {
                principal: principal.as_api_principal().clone(),
            },
            process_id,
            query.after_sequence.unwrap_or(0),
            limit,
        )
        .await
    {
        Ok(page) => Json(OutputPageWire {
            chunks: page
                .chunks()
                .iter()
                .map(|chunk| OutputChunkWire {
                    sequence: chunk.sequence(),
                    stream: match chunk.stream() {
                        ProcessOutputStream::Stdout => "stdout",
                        ProcessOutputStream::Stderr => "stderr",
                    },
                    text: chunk.text().to_owned(),
                })
                .collect(),
        })
        .into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

pub(super) async fn stop_process<H>(
    State(state): State<ProcessHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(process_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<StopBody>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    H: ProcessHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(value) => value,
        Err(code) => return bad_request(code, &request_id),
    };
    let process_id = match process_id.parse::<ProcessId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_process_id", &request_id),
    };
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    match state
        .host
        .stop_process(
            context,
            ExistingProcessCommand {
                process_id,
                expected_version: body.expected_version,
            },
        )
        .await
    {
        Ok(snapshot) => (StatusCode::ACCEPTED, Json(snapshot_to_wire(snapshot))).into_response(),
        Err(error) => host_error(error, &request_id),
    }
}

fn parse_start(body: StartBody) -> Result<StartProcessCommand, &'static str> {
    Ok(StartProcessCommand {
        workspace_id: body
            .workspace_id
            .parse()
            .map_err(|_| "invalid_workspace_id")?,
        task_run_id: body
            .task_run_id
            .parse()
            .map_err(|_| "invalid_task_run_id")?,
        attempt_id: body.attempt_id.parse().map_err(|_| "invalid_attempt_id")?,
        invocation_id: body
            .invocation_id
            .parse()
            .map_err(|_| "invalid_invocation_id")?,
    })
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

fn snapshot_to_wire(snapshot: ProcessSnapshot) -> SnapshotWire {
    SnapshotWire {
        process_id: snapshot.process_id.to_string(),
        invocation_id: snapshot.invocation_id.to_string(),
        workspace_id: snapshot.workspace_id.to_string(),
        state: match snapshot.state {
            runne_api::ProcessState::Starting => "starting",
            runne_api::ProcessState::Running => "running",
            runne_api::ProcessState::Stopping => "stopping",
            runne_api::ProcessState::Exited => "exited",
            runne_api::ProcessState::Failed => "failed",
        },
        version: snapshot.version,
        next_output_sequence: snapshot.next_output_sequence,
    }
}

fn host_error(error: ProcessHostError, request_id: &RequestId) -> Response {
    let (status, code) = match error {
        ProcessHostError::NotFound => (StatusCode::NOT_FOUND, "process_not_found"),
        ProcessHostError::Conflict => (StatusCode::CONFLICT, "process_conflict"),
        ProcessHostError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
        ProcessHostError::InvalidLimit => (StatusCode::BAD_REQUEST, "invalid_process_output_limit"),
        ProcessHostError::InvalidOutput => (StatusCode::BAD_REQUEST, "invalid_process_output"),
        ProcessHostError::SizeLimit => (StatusCode::PAYLOAD_TOO_LARGE, "process_output_too_large"),
        ProcessHostError::Backpressure => (StatusCode::TOO_MANY_REQUESTS, "runtime_backpressure"),
        ProcessHostError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable"),
        ProcessHostError::InvariantViolation => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_invariant_violation",
        ),
    };
    canonical_error_response(status, code, request_id)
}
fn bad_request(code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(StatusCode::BAD_REQUEST, code, request_id)
}
