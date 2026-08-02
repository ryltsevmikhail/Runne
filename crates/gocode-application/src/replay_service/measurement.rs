/// Rejects an event variable representation that the current writer policy
/// cannot guarantee every configured replay reader can deliver.
pub fn validate_replay_writer_event_size(actual_bytes: usize) -> Result<(), ReplayError> {
    if actual_bytes > REPLAY_EVENT_VARIABLE_MAX_BYTES {
        return Err(ReplayError::Integrity(format!(
            "replay event variable representation exceeds writer maximum: actual={actual_bytes}, \
             maximum={REPLAY_EVENT_VARIABLE_MAX_BYTES}"
        )));
    }
    Ok(())
}

/// Reader-first readiness gate for the larger of the active writer policy and
/// the largest retained event variable representation.
pub fn validate_replay_reader_capacity(
    manifest: &RetentionManifest,
    frame_capacity_bytes: usize,
    page_capacity_bytes: usize,
    declared_overhead_bytes: usize,
) -> Result<(), ReplayError> {
    let required = manifest
        .maximum_encoded_event_bytes()
        .max(REPLAY_EVENT_VARIABLE_MAX_BYTES)
        .checked_add(declared_overhead_bytes)
        .ok_or_else(|| ReplayError::Integrity("replay capacity calculation overflow".to_owned()))?;
    if required > frame_capacity_bytes || required > page_capacity_bytes {
        return Err(ReplayError::Integrity(format!(
            "replay reader capacity insufficient: required={required}, \
             frame={frame_capacity_bytes}, page={page_capacity_bytes}"
        )));
    }
    Ok(())
}

/// Largest event variable representation across the canonical contract and
/// the current HTTP durable-payload transport, excluding admitted wrappers.
pub fn measured_conversation_replay_event_bytes(
    event: &ReplayEvent,
    payload: &ConversationEvent,
) -> Result<usize, ReplayError> {
    measured_canonical_replay_event_bytes(event, CanonicalReplayPayloadV1::from(payload))
}

/// Largest event variable representation across the canonical contract and
/// the current HTTP durable-payload transport, excluding admitted wrappers.
pub fn measured_taskrun_replay_event_bytes(
    event: &ReplayEvent,
    payload: &TaskRunEvent,
) -> Result<usize, ReplayError> {
    let payload = CanonicalReplayPayloadV1::try_from(payload)
        .map_err(|_| ReplayError::Integrity("invalid public TaskRun replay payload".to_owned()))?;
    measured_canonical_replay_event_bytes(event, payload)
}

fn measured_canonical_replay_event_bytes(
    event: &ReplayEvent,
    payload: CanonicalReplayPayloadV1,
) -> Result<usize, ReplayError> {
    let aggregate_type = match event.aggregate_type {
        1 => "taskRun",
        2 => "conversation",
        _ => {
            return Err(ReplayError::Integrity(
                "invalid canonical replay aggregate type".to_owned(),
            ));
        }
    };
    let correlation_type = match event.correlation_type {
        1 => "taskRun",
        2 => "conversation",
        _ => {
            return Err(ReplayError::Integrity(
                "invalid canonical replay correlation type".to_owned(),
            ));
        }
    };
    let sensitivity = match event.sensitivity {
        0 => "public",
        1 => "internal",
        2 => "sensitive",
        _ => {
            return Err(ReplayError::Integrity(
                "invalid canonical replay sensitivity".to_owned(),
            ));
        }
    };
    let payload = serde_json::to_value(payload)
        .map_err(|_| ReplayError::Integrity("encode canonical replay payload".to_owned()))?;
    let event_type = payload
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ReplayError::Integrity("canonical replay payload has no type".to_owned()))?;
    let uuid = |bytes: [u8; 16]| uuid::Uuid::from_bytes(bytes).to_string();
    let value = serde_json::json!({
        "aggregateId": uuid(event.aggregate_id),
        "aggregateType": aggregate_type,
        "causationEventId": event.causation_id.map(uuid),
        "correlationId": uuid(event.correlation_id),
        "correlationType": correlation_type,
        "eventId": uuid(event.event_id),
        "eventType": event_type,
        "integrityDigest": lower_hex(&event.integrity_digest),
        "payload": payload,
        "schemaVersion": event.schema_version,
        "sensitivity": sensitivity,
        "sequence": event.sequence,
        "timestampUnixMicros": event.timestamp,
    });
    let canonical_bytes = serde_json::to_vec(&value)
        .map(|encoded| encoded.len())
        .map_err(|_| ReplayError::Integrity("encode canonical replay event".to_owned()))?;
    let durable_payload_hex_bytes = event.payload.len().checked_mul(2).ok_or_else(|| {
        ReplayError::Integrity("replay transport payload size overflow".to_owned())
    })?;
    Ok(canonical_bytes.max(durable_payload_hex_bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(*byte >> 4)]));
        output.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    output
}
