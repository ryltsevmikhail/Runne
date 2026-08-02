use super::wire::CanonicalEventWire;
use super::{
    CURSOR_PREFIX, CanonicalId, CanonicalReplayEvent, CanonicalReplayPayload,
    ConversationReplayPayload, Digest, HashSet, MAXIMUM_CURSOR_BYTES, MAXIMUM_EVENT_TYPE_BYTES,
    MAXIMUM_REASON_BYTES, MAXIMUM_TEXT_BYTES, ReplayAggregateKind, ReplayClientError,
    ReplayClientErrorKind, ReplaySensitivity, Sha256, TaskRunReplayPayload,
};
mod payload;

pub(super) fn validate_exact_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
) -> Result<(), ReplayClientError> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    Ok(())
}

pub(super) fn validate_exact_keys_with_extra(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
    extra: &str,
) -> Result<(), ReplayClientError> {
    if object.len() != expected.len().saturating_add(1)
        || !object.contains_key(extra)
        || expected.iter().any(|key| !object.contains_key(*key))
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    Ok(())
}

pub(super) fn validate_canonical_event(
    wire: CanonicalEventWire,
) -> Result<CanonicalReplayEvent, ReplayClientError> {
    if wire.schema_version != 1 {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    let aggregate_kind = ReplayAggregateKind::parse(&wire.aggregate_type)?;
    let aggregate_id = parse_uuid_v7(&wire.aggregate_id)?;
    let event_id = parse_uuid_v7(&wire.event_id)?;
    let causation_event_id = wire
        .causation_event_id
        .as_deref()
        .map(parse_uuid_v7)
        .transpose()?;
    let correlation_id = parse_uuid_v7(&wire.correlation_id)?;
    let correlation_kind = ReplayAggregateKind::parse(&wire.correlation_type)?;
    if wire.sequence == 0 {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::NonMonotonicSequence,
        ));
    }
    if wire.event_type.is_empty()
        || wire.event_type.len() > MAXIMUM_EVENT_TYPE_BYTES
        || wire.event_type.chars().any(char::is_control)
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    let sensitivity = match wire.sensitivity.as_str() {
        "public" => ReplaySensitivity::Public,
        "internal" => ReplaySensitivity::Internal,
        "sensitive" => ReplaySensitivity::Sensitive,
        _ => {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::SchemaMismatch,
            ));
        }
    };
    let integrity_digest = decode_lower_hex::<32>(&wire.integrity_digest)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::Integrity))?;
    if decode_lower_hex::<16>(&wire.replay_binding_id)
        .as_ref()
        .is_none_or(|value| *value == [0; 16])
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::BindingMismatch,
        ));
    }
    let payload_type = wire
        .payload
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    if payload_type != wire.event_type {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    let payload =
        payload::validate_payload(aggregate_kind, &wire.event_type, wire.payload.clone())?;
    let mut canonical_value = serde_json::to_value(&wire)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Integrity))?;
    canonical_value
        .as_object_mut()
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::Integrity))?
        .remove("replayBindingId");
    let canonical_bytes = serde_json::to_vec(&canonical_value)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Integrity))?;
    let canonical_digest = Sha256::digest(&canonical_bytes).into();

    Ok(CanonicalReplayEvent {
        event_id,
        aggregate_kind,
        aggregate_id,
        sequence: wire.sequence,
        timestamp_unix_micros: wire.timestamp_unix_micros,
        sensitivity,
        event_type: wire.event_type,
        causation_event_id,
        correlation_id,
        correlation_kind,
        payload,
        integrity_digest,
        canonical_bytes,
        canonical_digest,
    })
}

pub(super) fn parse_uuid_v7(value: &str) -> Result<CanonicalId, ReplayClientError> {
    let id = CanonicalId::parse(value)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    if id.to_string() != value {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    Ok(id)
}

pub(super) fn decode_lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.saturating_mul(2)
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).ok()?;
    Some(bytes)
}

pub(super) fn validate_bounded_lower_hex(
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ReplayClientError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || !value.len().is_multiple_of(2)
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::InvalidResponse,
        ));
    }
    Ok(())
}

pub(super) fn validate_cursor(value: &str) -> Result<(), ReplayClientError> {
    if value.len() > MAXIMUM_CURSOR_BYTES {
        return Err(ReplayClientError::new(ReplayClientErrorKind::CursorInvalid));
    }
    let encoded = value
        .strip_prefix(CURSOR_PREFIX)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::CursorInvalid))?;
    if encoded.is_empty()
        || !encoded.len().is_multiple_of(2)
        || encoded
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ReplayClientError::new(ReplayClientErrorKind::CursorInvalid));
    }
    let bytes = hex::decode(encoded)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::CursorInvalid))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::CursorInvalid))?;
    if !value.is_object() {
        return Err(ReplayClientError::new(ReplayClientErrorKind::CursorInvalid));
    }
    Ok(())
}
