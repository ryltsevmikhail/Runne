#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResumeFromBaselineRequest {
    baseline: ResumeBaselineWireV2,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResumeBaselineWireV2 {
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
