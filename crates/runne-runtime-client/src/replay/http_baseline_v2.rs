#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselineV2Wire {
    schema_version: u8,
    authority_id: String,
    principal_id: String,
    lineage_id: String,
    runtime_session_binding_digest: String,
    replay_scope_digest: String,
    aggregate_kind: String,
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
fn decode_baseline_wire_v2(
    value: serde_json::Value,
) -> Result<runne_api::ReplayRetentionBaselineWireV2, ()> {
    let v: BaselineV2Wire = serde_json::from_value(value).map_err(|_| ())?;
    let h16 = |x: &str| decode_lower_hex::<16>(x).ok_or(());
    let h32 = |x: &str| decode_lower_hex::<32>(x).ok_or(());
    let kind = match v.aggregate_kind.as_str() {
        "conversation" => runne_api::ApiReplayAggregateKind::Conversation,
        "taskRun" => runne_api::ApiReplayAggregateKind::TaskRun,
        _ => return Err(()),
    };
    Ok(
        runne_api::ReplayRetentionBaselineWireV2::from_unauthenticated_fields(
            runne_api::UnauthenticatedReplayRetentionBaselineFieldsV2 {
                schema_version: v.schema_version,
                authority_id: h16(&v.authority_id)?,
                principal_id: v.principal_id,
                lineage_id: h16(&v.lineage_id)?,
                runtime_session_binding_digest: h32(&v.runtime_session_binding_digest)?,
                replay_scope_digest: h32(&v.replay_scope_digest)?,
                aggregate_kind: kind,
                aggregate_id: h16(&v.aggregate_id)?,
                sequence: v.sequence,
                version: v.version,
                baseline_global_position: v.baseline_global_position,
                head_event_id: h16(&v.head_event_id)?,
                head_integrity_digest: h32(&v.head_integrity_digest)?,
                promotion_codec: v.promotion_codec,
                promotion_projection_bytes: URL_SAFE_NO_PAD
                    .decode(v.promotion_projection_bytes)
                    .map_err(|_| ())?,
                promotion_projection_digest: h32(&v.promotion_projection_digest)?,
                retained_floor: v.retained_floor,
                captured_high_water: v.captured_high_water,
                retention_generation: v.retention_generation,
                retention_manifest_digest: h32(&v.retention_manifest_digest)?,
                issued_at_unix_ms: v.issued_at_unix_ms,
                expires_at_unix_ms: v.expires_at_unix_ms,
                witness_mac: h32(&v.witness_mac)?,
            },
        ),
    )
}
