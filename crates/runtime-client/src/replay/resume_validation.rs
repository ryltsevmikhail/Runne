pub(super) struct AppliedSuffix {
    pub(super) cursor: Option<super::ReplayCursor>,
    pub(super) last_event: Option<([u8; 16], [u8; 32], u64, i64)>,
}

pub(super) fn parse_baseline_checkpoint(
    cursor: &str,
    _baseline: &super::ReplayRetentionBaselineV2,
) -> Result<gocode_api::UnauthenticatedReplayBaselineCheckpointFactsV2, super::ReplayClientError> {
    let value = cursor_json(cursor)?;
    let aggregate_id = bytes16(
        field(&value, "scope")?
            .get("Aggregate")
            .and_then(|scope| scope.get("aggregate_id"))
            .ok_or_else(invalid_cursor)?,
    )?;
    let aggregate_type = field(&value, "scope")?
        .get("Aggregate")
        .and_then(|scope| scope.get("aggregate_type"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(invalid_cursor)?;
    let aggregate_kind = match aggregate_type {
        1 => gocode_api::ApiReplayAggregateKind::TaskRun,
        2 => gocode_api::ApiReplayAggregateKind::Conversation,
        _ => return Err(invalid_cursor()),
    };
    Ok(gocode_api::UnauthenticatedReplayBaselineCheckpointFactsV2 {
        cursor: cursor.to_owned(),
        aggregate_kind,
        aggregate_id,
        event_id: uuid16(field(&value, "event_id")?)?,
        sequence: field(&value, "sequence")?
            .as_u64()
            .ok_or_else(invalid_cursor)?,
        global_position: field(&value, "global_position")?
            .as_i64()
            .ok_or_else(invalid_cursor)?,
    })
}

pub(super) fn replay_cursor_global_position(
    cursor: &super::ReplayCursor,
) -> Result<i64, super::ReplayClientError> {
    field(&cursor_json(&cursor.0)?, "global_position")?
        .as_i64()
        .filter(|position| *position > 0)
        .ok_or_else(invalid_cursor)
}

fn cursor_json(cursor: &str) -> Result<serde_json::Value, super::ReplayClientError> {
    let encoded = cursor
        .strip_prefix("gocode-replay-cursor-v1.")
        .ok_or_else(invalid_cursor)?;
    let bytes = hex::decode(encoded).map_err(|_| invalid_cursor())?;
    serde_json::from_slice(&bytes).map_err(|_| invalid_cursor())
}

fn field<'a>(
    value: &'a serde_json::Value,
    name: &str,
) -> Result<&'a serde_json::Value, super::ReplayClientError> {
    value.get(name).ok_or_else(invalid_cursor)
}

fn bytes16(value: &serde_json::Value) -> Result<[u8; 16], super::ReplayClientError> {
    let bytes = value
        .as_array()
        .ok_or_else(invalid_cursor)?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or_else(invalid_cursor)
        })
        .collect::<Result<Vec<_>, _>>()?;
    bytes.try_into().map_err(|_| invalid_cursor())
}

fn uuid16(value: &serde_json::Value) -> Result<[u8; 16], super::ReplayClientError> {
    let value = value.as_str().ok_or_else(invalid_cursor)?;
    uuid::Uuid::parse_str(value)
        .map(uuid::Uuid::into_bytes)
        .map_err(|_| invalid_cursor())
}

const fn invalid_cursor() -> super::ReplayClientError {
    super::ReplayClientError::new(super::ReplayClientErrorKind::CursorInvalid)
}
