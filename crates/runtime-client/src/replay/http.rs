use super::validation::parse_uuid_v7;
use super::wire::ErrorEnvelopeWire;
use super::{
    CONTENT_TYPE, MAXIMUM_ERROR_RESPONSE_BYTES, MAXIMUM_REPLAY_RESPONSE_BYTES, ReplayClientError,
    ReplayClientErrorKind, SseDecodeError,
};

pub(super) async fn read_replay_json<T>(response: reqwest::Response) -> Result<T, ReplayClientError>
where
    T: serde::de::DeserializeOwned,
{
    if response.status().as_u16() != 200 {
        return Err(read_replay_error(response).await);
    }
    ensure_content_type(&response, "application/json")?;
    let body = read_bounded(response, MAXIMUM_REPLAY_RESPONSE_BYTES).await?;
    serde_json::from_slice(&body)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

pub(super) async fn read_replay_error(response: reqwest::Response) -> ReplayClientError {
    let status = response.status().as_u16();
    if ensure_content_type(&response, "application/json").is_err() {
        return ReplayClientError::new(ReplayClientErrorKind::UnexpectedContentType);
    }
    let body = match read_bounded(response, MAXIMUM_ERROR_RESPONSE_BYTES).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    let envelope: ErrorEnvelopeWire = match serde_json::from_slice(&body) {
        Ok(envelope) => envelope,
        Err(_) => return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse),
    };
    if parse_uuid_v7(&envelope.request_id).is_err() {
        return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse);
    }
    let kind = match (status, envelope.code.as_str()) {
        (
            400,
            "invalid_request"
            | "invalid_aggregate_id"
            | "unsupported_replay_scope"
            | "invalid_replay_page_limit"
            | "invalid_replay_session_id",
        )
        | (413, "request_too_large") => ReplayClientErrorKind::InvalidRequest,
        (401, "unauthorized" | "replay_authorization_revoked") => {
            ReplayClientErrorKind::AuthorizationRevoked
        }
        (403, "replay_sensitivity_denied") => ReplayClientErrorKind::SensitivityDenied,
        (404, "replay_session_not_found")
        | (409, "replay_session_conflict")
        | (410, "replay_session_expired") => ReplayClientErrorKind::SessionExpired,
        (409, "replay_unsupported_schema") => ReplayClientErrorKind::SchemaMismatch,
        (400, "invalid_replay_cursor") | (409, "replay_cursor_regression") => {
            ReplayClientErrorKind::CursorInvalid
        }
        (409, "replay_page_in_progress") | (429 | 503, "replay_backpressure") => {
            ReplayClientErrorKind::Backpressure
        }
        (410, "replay_retention_gap") => ReplayClientErrorKind::RetentionGap,
        (503, "runtime_unavailable") => ReplayClientErrorKind::Transport,
        (500, "runtime_invariant_violation") => ReplayClientErrorKind::Integrity,
        _ => ReplayClientErrorKind::InvalidResponse,
    };
    ReplayClientError::new(kind)
}

pub(super) async fn read_bounded(
    mut response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ReplayClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(maximum_bytes).unwrap_or(u64::MAX))
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::ResponseTooLarge,
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?
    {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::ResponseTooLarge,
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(super) fn ensure_content_type(
    response: &reqwest::Response,
    expected: &str,
) -> Result<(), ReplayClientError> {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some(expected) {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::UnexpectedContentType,
        ));
    }
    Ok(())
}

pub(super) const fn map_sse_decode_error(error: SseDecodeError) -> ReplayClientError {
    let kind = match error {
        SseDecodeError::FrameTooLarge => ReplayClientErrorKind::ResponseTooLarge,
        SseDecodeError::UnknownEvent => ReplayClientErrorKind::SchemaMismatch,
        SseDecodeError::InvalidUtf8
        | SseDecodeError::Nul
        | SseDecodeError::InvalidLineEnding
        | SseDecodeError::UnknownField
        | SseDecodeError::MissingEvent
        | SseDecodeError::MissingData
        | SseDecodeError::MultipleData
        | SseDecodeError::DataAfterTerminal
        | SseDecodeError::IncompleteFrame => ReplayClientErrorKind::Integrity,
    };
    ReplayClientError::new(kind)
}
