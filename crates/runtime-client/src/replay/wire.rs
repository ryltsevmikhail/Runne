use super::validation::{
    decode_lower_hex, validate_cursor, validate_exact_keys, validate_exact_keys_with_extra,
};
use super::{
    Deserialize, LiveDeliveryId, ReplayClientError, ReplayClientErrorKind, ReplayCursor, Serialize,
};

pub(super) fn cursor(value: String) -> Result<ReplayCursor, ReplayClientError> {
    validate_cursor(&value)?;
    Ok(ReplayCursor(value))
}

pub(super) fn cursor_value(cursor: &ReplayCursor) -> &str {
    &cursor.0
}

pub(super) fn session_id(value: &str) -> Result<super::ReplaySessionId, ReplayClientError> {
    let bytes = decode_lower_hex::<16>(value)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse))?;
    if bytes == [0; 16] {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::InvalidResponse,
        ));
    }
    Ok(super::ReplaySessionId(bytes))
}

pub(super) fn session_value(value: &super::ReplaySessionId) -> String {
    hex::encode(value.0)
}

pub(super) fn live_id(value: &str) -> Result<LiveDeliveryId, ReplayClientError> {
    let id = super::validation::parse_uuid_v7(value)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse))?;
    Ok(LiveDeliveryId(id))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct OpenSessionRequestWire<'a> {
    pub(super) aggregate_type: &'static str,
    pub(super) aggregate_id: String,
    pub(super) from_cursor: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct OpenSessionResponseWire {
    pub(super) session_id: String,
    pub(super) high_water_ref: String,
    pub(super) events: Vec<serde_json::Value>,
    pub(super) has_more: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ReadPageRequestWire {
    pub(super) limit: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ReadPageResponseWire {
    pub(super) events: Vec<serde_json::Value>,
    pub(super) has_more: bool,
}

#[derive(Serialize)]
pub(super) struct AcknowledgeRequestWire<'a> {
    pub(super) cursor: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AcknowledgeResponseWire {
    pub(super) acknowledged: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CompleteCatchUpResponseWire {
    pub(super) catch_up_proof: String,
    pub(super) session_state: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ContinueLiveResponseWire {
    pub(super) live_delivery_id: String,
    pub(super) session_state: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CanonicalEventWire {
    pub(super) event_id: String,
    pub(super) aggregate_type: String,
    pub(super) aggregate_id: String,
    pub(super) sequence: u64,
    pub(super) timestamp_unix_micros: i64,
    pub(super) sensitivity: String,
    pub(super) schema_version: u32,
    pub(super) event_type: String,
    pub(super) causation_event_id: Option<String>,
    pub(super) integrity_digest: String,
    pub(super) correlation_id: String,
    pub(super) correlation_type: String,
    pub(super) payload: serde_json::Value,
    pub(super) replay_binding_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SseDeliveryWire {
    pub(super) transport_version: u32,
    pub(super) replay_session_id: String,
    pub(super) live_delivery_id: Option<String>,
    pub(super) delivery_sequence: u64,
    pub(super) canonical_event: serde_json::Value,
    pub(super) replay_cursor: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SseTerminalWire {
    pub(super) transport_version: u32,
    pub(super) code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ErrorEnvelopeWire {
    pub(super) code: String,
    pub(super) request_id: String,
}

pub(super) const EVENT_KEYS: &[&str] = &[
    "aggregateId",
    "aggregateType",
    "causationEventId",
    "correlationId",
    "correlationType",
    "eventId",
    "eventType",
    "integrityDigest",
    "payload",
    "replayBindingId",
    "schemaVersion",
    "sensitivity",
    "sequence",
    "timestampUnixMicros",
];

pub(super) fn parse_http_delivery(
    mut value: serde_json::Value,
) -> Result<(CanonicalEventWire, String), ReplayClientError> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    validate_exact_keys_with_extra(object, EVENT_KEYS, "cursor")?;
    let cursor = object
        .remove("cursor")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::CursorInvalid))?;
    let event = serde_json::from_value(value)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    Ok((event, cursor))
}

pub(super) fn parse_sse_event(
    value: serde_json::Value,
) -> Result<CanonicalEventWire, ReplayClientError> {
    let object = value
        .as_object()
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    validate_exact_keys(object, EVENT_KEYS)?;
    serde_json::from_value(value)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}
