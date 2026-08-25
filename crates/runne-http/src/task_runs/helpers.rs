fn command_context(
    headers: &HeaderMap,
    principal: &AuthenticatedPrincipal,
    actor: &ApiActor,
) -> Result<TaskRunCommandContext, &'static str> {
    let command_id = exactly_one_header(headers, "x-command-id")
        .and_then(|value| value.parse::<CommandId>().ok())
        .ok_or("invalid_command_id")?;
    let idempotency_key = exactly_one_header(headers, "idempotency-key")
        .and_then(|value| IdempotencyKey::new(value).ok())
        .ok_or("invalid_idempotency_key")?;
    Ok(TaskRunCommandContext {
        command_id,
        idempotency_key,
        principal: principal.as_api_principal().clone(),
        actor: actor.clone(),
    })
}

fn exactly_one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn command_response(
    result: Result<TaskRunCommandAck, TaskRunHostError>,
    request_id: &RequestId,
) -> Response {
    match result {
        Ok(ack) => (StatusCode::ACCEPTED, Json(ack_to_wire(ack))).into_response(),
        Err(error) => host_error_response(error, request_id),
    }
}

fn ack_to_wire(ack: TaskRunCommandAck) -> TaskRunAckWire {
    let (transition, attempt_id, terminal_result) = match ack.kind {
        TaskRunCommandAckKind::Created => ("created", None, None),
        TaskRunCommandAckKind::Queued => ("queued", None, None),
        TaskRunCommandAckKind::CancellationRequested => {
            ("cancellation_requested", None, None)
        }
        TaskRunCommandAckKind::Admitted => ("admitted", None, None),
        TaskRunCommandAckKind::AttemptStarted { attempt_id } => {
            ("attempt_started", Some(attempt_id.to_string()), None)
        }
        TaskRunCommandAckKind::Completed { result } => {
            ("completed", None, Some(terminal_result_to_wire(result)))
        }
    };
    TaskRunAckWire {
        task_run_id: ack.taskrun_id.to_string(),
        stream_version: ack.new_version,
        transition,
        attempt_id,
        terminal_result,
    }
}

fn snapshot_to_wire(snapshot: TaskRunSnapshot) -> TaskRunSnapshotWire {
    TaskRunSnapshotWire {
        task_run_id: snapshot.taskrun_id.to_string(),
        state: state_name(snapshot.state),
        stream_version: snapshot.stream_version,
        active_attempt_id: snapshot.active_attempt_id.map(|id| id.to_string()),
        terminal_result: snapshot.terminal_result.map(terminal_result_to_wire),
    }
}

fn state_name(state: CanonicalTaskRunState) -> &'static str {
    state.as_str()
}

fn terminal_result_to_wire(result: CanonicalTerminalResult) -> TerminalResultWire {
    match result {
        CanonicalTerminalResult::Success => TerminalResultWire::Success,
        CanonicalTerminalResult::Failure { reason } => TerminalResultWire::Failure { reason },
    }
}

fn host_error_response(error: TaskRunHostError, request_id: &RequestId) -> Response {
    let status = match error {
        TaskRunHostError::NotFound => StatusCode::NOT_FOUND,
        TaskRunHostError::Conflict => StatusCode::CONFLICT,
        TaskRunHostError::Backpressure | TaskRunHostError::Unavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        TaskRunHostError::InvariantViolation => StatusCode::INTERNAL_SERVER_ERROR,
    };
    canonical_error_response(status, error.code(), request_id)
}

fn bad_request(code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(StatusCode::BAD_REQUEST, code, request_id)
}
