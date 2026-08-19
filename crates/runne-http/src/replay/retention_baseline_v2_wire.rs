#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayRetentionGapV2Response<'a> {
    code: &'static str,
    request_id: &'a str,
    baseline: ReplayRetentionBaselineV2Response<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayRetentionBaselineV2Response<'a> {
    schema_version: u8,
    authority_id: String,
    principal_id: &'a str,
    lineage_id: String,
    runtime_session_binding_digest: String,
    replay_scope_digest: String,
    aggregate_kind: &'static str,
    aggregate_id: String,
    sequence: u64,
    version: u64,
    baseline_global_position: i64,
    head_event_id: String,
    head_integrity_digest: String,
    promotion_codec: u8,
    promotion_projection_bytes: String,
    promotion_projection_digest: String,
    retained_floor: i64,
    captured_high_water: i64,
    retention_generation: u64,
    retention_manifest_digest: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    witness_mac: String,
}

fn retention_baseline_v2_response(
    baseline: &runne_api::ReplayRetentionBaselineWireV2,
    request_id: &RequestId,
    prohibited_content: &dyn ProhibitedContentPort,
) -> Result<Response, ReplayHttpFailure> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let fields = baseline.to_unauthenticated_fields();
    inspect_replay_bytes(prohibited_content, &fields.promotion_projection_bytes)
        .map_err(|error| replay_error_to_http(&error))?;
    let aggregate_kind = match fields.aggregate_kind {
        runne_api::ApiReplayAggregateKind::Conversation => "conversation",
        runne_api::ApiReplayAggregateKind::TaskRun => "taskRun",
    };
    let response = ReplayRetentionGapV2Response {
        code: "replay_retention_gap",
        request_id: request_id.as_str(),
        baseline: ReplayRetentionBaselineV2Response {
            schema_version: fields.schema_version,
            authority_id: hex::encode(fields.authority_id),
            principal_id: &fields.principal_id,
            lineage_id: hex::encode(fields.lineage_id),
            runtime_session_binding_digest: hex::encode(fields.runtime_session_binding_digest),
            replay_scope_digest: hex::encode(fields.replay_scope_digest),
            aggregate_kind,
            aggregate_id: hex::encode(fields.aggregate_id),
            sequence: fields.sequence,
            version: fields.version,
            baseline_global_position: fields.baseline_global_position,
            head_event_id: hex::encode(fields.head_event_id),
            head_integrity_digest: hex::encode(fields.head_integrity_digest),
            promotion_codec: fields.promotion_codec,
            promotion_projection_bytes: URL_SAFE_NO_PAD.encode(fields.promotion_projection_bytes),
            promotion_projection_digest: hex::encode(fields.promotion_projection_digest),
            retained_floor: fields.retained_floor,
            captured_high_water: fields.captured_high_water,
            retention_generation: fields.retention_generation,
            retention_manifest_digest: hex::encode(fields.retention_manifest_digest),
            issued_at_unix_ms: fields.issued_at_unix_ms,
            expires_at_unix_ms: fields.expires_at_unix_ms,
            witness_mac: hex::encode(fields.witness_mac),
        },
    };
    let bytes = serde_json::to_vec(&response).map_err(|_| replay_invariant_violation())?;
    if bytes.len() > MAX_RETENTION_BASELINE_RESPONSE_BYTES {
        return Err(replay_backpressure());
    }
    inspect_replay_bytes(prohibited_content, &bytes)
        .map_err(|error| replay_error_to_http(&error))?;
    Ok((
        StatusCode::GONE,
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (
                axum::http::HeaderName::from_static("x-request-id"),
                request_id.as_str(),
            ),
        ],
        bytes,
    )
        .into_response())
}
