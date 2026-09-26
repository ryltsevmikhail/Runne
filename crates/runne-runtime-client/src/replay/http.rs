use super::strict_json::reject_duplicate_keys;
use super::validation::{decode_lower_hex, parse_uuid_v7};
use super::wire::ErrorEnvelopeWire;
use super::{
    CONTENT_TYPE, MAXIMUM_ERROR_RESPONSE_BYTES, MAXIMUM_REPLAY_RESPONSE_BYTES, ReplayClientError,
    ReplayClientErrorKind, ReplayScope, SseDecodeError,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub(super) async fn read_replay_json<T>(response: reqwest::Response) -> Result<T, ReplayClientError>
where
    T: serde::de::DeserializeOwned,
{
    if response.status().as_u16() != 200 {
        return Err(read_replay_error(response).await);
    }
    ensure_content_type(&response, "application/json")?;
    let body = read_bounded(response, MAXIMUM_REPLAY_RESPONSE_BYTES).await?;
    reject_duplicate_keys(&body)
        .map_err(|()| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    serde_json::from_slice(&body)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

pub(super) async fn read_resume_json(
    response: reqwest::Response,
) -> Result<super::wire::ResumeFromBaselineResponseWire, ReplayClientError> {
    if response.status().as_u16() != 200 {
        return Err(read_replay_error(response).await);
    }
    if !super::http_retention::has_exact_retention_content_type(&response)
        || !super::http_retention::has_exact_no_store(&response)
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::UnexpectedContentType,
        ));
    }
    let Some(request_id) = super::http_retention::retention_request_id(&response) else {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::InvalidResponse,
        ));
    };
    let body = read_bounded(response, MAXIMUM_REPLAY_RESPONSE_BYTES).await?;
    reject_duplicate_keys(&body)
        .map_err(|()| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    let response: super::wire::ResumeFromBaselineResponseWire = serde_json::from_slice(&body)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    if parse_uuid_v7(&response.request_id).is_err() || response.request_id != request_id {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::InvalidResponse,
        ));
    }
    Ok(response)
}

pub(super) async fn read_open_session_json<T>(
    response: reqwest::Response,
    authority: &crate::canonical::RuntimeSessionAuthority,
    scope: ReplayScope,
) -> Result<T, ReplayClientError>
where
    T: serde::de::DeserializeOwned,
{
    if response.status().as_u16() == 200 {
        return read_replay_json(response).await;
    }
    Err(read_open_session_error(response, authority, scope).await)
}

pub(super) async fn read_replay_error(response: reqwest::Response) -> ReplayClientError {
    let status = response.status().as_u16();
    let error = read_replay_error_inner(response, status).await;
    super::http_diagnostics::report_replay_error(status, &error);
    error
}

async fn read_replay_error_inner(response: reqwest::Response, status: u16) -> ReplayClientError {
    if ensure_content_type(&response, "application/json").is_err() {
        return ReplayClientError::new(ReplayClientErrorKind::UnexpectedContentType);
    }
    let body = match read_bounded(response, MAXIMUM_ERROR_RESPONSE_BYTES).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    if reject_duplicate_keys(&body).is_err() {
        return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse);
    }
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
        (503, "runtime_unavailable") => ReplayClientErrorKind::Transport,
        (500, "runtime_invariant_violation") => ReplayClientErrorKind::Integrity,
        _ => ReplayClientErrorKind::InvalidResponse,
    };
    ReplayClientError::new(kind)
}

async fn read_open_session_error(
    response: reqwest::Response,
    authority: &crate::canonical::RuntimeSessionAuthority,
    scope: ReplayScope,
) -> ReplayClientError {
    if response.status().as_u16() != 410 {
        return read_replay_error(response).await;
    }
    if !super::http_retention::has_exact_retention_content_type(&response) {
        return ReplayClientError::new(ReplayClientErrorKind::UnexpectedContentType);
    }
    let Some(request_id) = super::http_retention::retention_request_id(&response) else {
        return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse);
    };
    let body = match read_bounded(response, MAXIMUM_REPLAY_RESPONSE_BYTES).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    if reject_duplicate_keys(&body).is_err() {
        return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse);
    }
    let envelope: ErrorEnvelopeWire = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse),
    };
    if envelope.code != "replay_retention_gap"
        || parse_uuid_v7(&envelope.request_id).is_err()
        || envelope.request_id != request_id
    {
        return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse);
    }
    let Some(baseline) = envelope.baseline else {
        return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse);
    };
    let Ok(wire) = decode_baseline_wire(baseline) else {
        return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse);
    };
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(value) => u64::try_from(value.as_millis()).unwrap_or(u64::MAX),
        Err(_) => return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse),
    };
    match wire {
        BaselineWire::V1(wire) => authority
            .verify_replay_retention_baseline(&wire, scope, now)
            .map_or_else(
                |_| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse),
                ReplayClientError::retention_gap,
            ),
        BaselineWire::V2(wire) => authority
            .verify_replay_retention_baseline_v2(&wire, scope, now)
            .map_or_else(
                |_| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse),
                ReplayClientError::retention_gap_v2,
            ),
    }
}

enum BaselineWire {
    V1(runne_api::ReplayRetentionBaselineWireV1),
    V2(runne_api::ReplayRetentionBaselineWireV2),
}

fn decode_baseline_wire(value: serde_json::Value) -> Result<BaselineWire, ()> {
    if value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        == Some(2)
    {
        return decode_baseline_wire_v2(value).map(BaselineWire::V2);
    }
    let value: super::wire::ReplayRetentionBaselineWire =
        serde_json::from_value(value).map_err(|_| ())?;
    let hex16 = |value: &str| decode_lower_hex::<16>(value);
    let hex32 = |value: &str| decode_lower_hex::<32>(value);
    let aggregate_kind = match value.aggregate_kind.as_str() {
        "conversation" => runne_api::ApiReplayAggregateKind::Conversation,
        "taskRun" => runne_api::ApiReplayAggregateKind::TaskRun,
        _ => return Err(()),
    };
    Ok(BaselineWire::V1(
        runne_api::ReplayRetentionBaselineWireV1::from_unauthenticated_fields(
            runne_api::UnauthenticatedReplayRetentionBaselineFieldsV1 {
                schema_version: value.schema_version,
                authority_id: hex16(&value.authority_id).ok_or(())?,
                principal_id: value.principal_id,
                lineage_id: hex16(&value.lineage_id).ok_or(())?,
                runtime_session_binding_digest: hex32(&value.runtime_session_binding_digest)
                    .ok_or(())?,
                replay_scope_digest: hex32(&value.replay_scope_digest).ok_or(())?,
                aggregate_kind,
                aggregate_id: hex16(&value.aggregate_id).ok_or(())?,
                sequence: value.sequence,
                version: value.version,
                baseline_global_position: value.baseline_global_position,
                projection_codec: value.projection_codec,
                projection_bytes: URL_SAFE_NO_PAD
                    .decode(value.projection_bytes)
                    .map_err(|_| ())?,
                projection_digest: hex32(&value.projection_digest).ok_or(())?,
                retained_floor: value.retained_floor,
                captured_high_water: value.captured_high_water,
                retention_generation: value.retention_generation,
                retention_witness: hex32(&value.retention_witness).ok_or(())?,
                issued_at_unix_ms: value.issued_at_unix_ms,
                expires_at_unix_ms: value.expires_at_unix_ms,
                witness_mac: hex32(&value.witness_mac).ok_or(())?,
            },
        ),
    ))
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

include!("http_baseline_v2.rs");
