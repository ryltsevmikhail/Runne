fn replay_unsupported_schema() -> ReplayHttpFailure {
    ReplayHttpFailure::new(StatusCode::CONFLICT, "replay_unsupported_schema")
}

fn replay_authorization_revoked() -> ReplayHttpFailure {
    ReplayHttpFailure::new(StatusCode::UNAUTHORIZED, "replay_authorization_revoked")
}

fn replay_backpressure() -> ReplayHttpFailure {
    ReplayHttpFailure::new(StatusCode::TOO_MANY_REQUESTS, "replay_backpressure")
}

fn map_json_rejection(rejection: JsonRejection) -> ReplayHttpFailure {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ReplayHttpFailure::new(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large")
    } else {
        ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request")
    }
}

fn replay_http_failure_to_delivery_error(error: ReplayHttpFailure) -> ReplayError {
    match error.code {
        "replay_unsupported_schema" => {
            ReplayError::Integrity("unsupported replay schema".to_owned())
        }
        "replay_authorization_revoked" => ReplayError::AuthorizationRevoked,
        "replay_backpressure" => ReplayError::BackpressureExceeded,
        _ => replay_delivery_integrity_error(),
    }
}

fn replay_error_to_http(error: &ReplayError) -> ReplayHttpFailure {
    match error {
        ReplayError::SessionNotFound => {
            ReplayHttpFailure::new(StatusCode::NOT_FOUND, "replay_session_not_found")
        }
        ReplayError::Unauthorized(_) => {
            ReplayHttpFailure::new(StatusCode::UNAUTHORIZED, "unauthorized")
        }
        ReplayError::AuthorizationRevoked => replay_authorization_revoked(),
        ReplayError::InvalidState(_) | ReplayError::NotAcknowledged => {
            ReplayHttpFailure::new(StatusCode::CONFLICT, "replay_session_conflict")
        }
        ReplayError::AlreadyAcknowledged => {
            ReplayHttpFailure::new(StatusCode::CONFLICT, "replay_cursor_regression")
        }
        ReplayError::StaleGeneration | ReplayError::StreamTerminated => {
            ReplayHttpFailure::new(StatusCode::GONE, "replay_session_expired")
        }
        ReplayError::ReplayRetentionGap { .. } => {
            ReplayHttpFailure::new(StatusCode::GONE, "replay_retention_gap")
        }
        ReplayError::Storage(_) => {
            ReplayHttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable")
        }
        ReplayError::Integrity(message) if message == "unsupported replay schema" => {
            replay_unsupported_schema()
        }
        ReplayError::Integrity(_) => replay_invariant_violation(),
        ReplayError::CursorInvalid { .. } => invalid_replay_cursor(),
        ReplayError::SensitivityDenied => {
            ReplayHttpFailure::new(StatusCode::FORBIDDEN, "replay_sensitivity_denied")
        }
        ReplayError::BackpressureExceeded => replay_backpressure(),
    }
}

fn replay_error_terminates_session(error: &ReplayError) -> bool {
    matches!(
        error,
        ReplayError::SessionNotFound
            | ReplayError::AuthorizationRevoked
            | ReplayError::StaleGeneration
            | ReplayError::ReplayRetentionGap { .. }
            | ReplayError::Integrity(_)
            | ReplayError::StreamTerminated
    )
}
