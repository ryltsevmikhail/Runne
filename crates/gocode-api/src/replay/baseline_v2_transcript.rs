/// Canonical domain separation used before deriving a V2 session-bound resume key.
pub const REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V2: &[u8] =
    b"gocode.replay-retention-baseline-resume.key.v2\0";

/// Returns the exact length-framed unauthenticated V2 resume claim transcript.
pub fn replay_retention_baseline_v2_transcript(
    wire: &ReplayRetentionBaselineWireV2,
) -> Result<Vec<u8>, ReplayRetentionBaselineWireError> {
    let value = wire.unauthenticated_fields();
    if value.principal_id.is_empty()
        || value.principal_id.len() > 256
        || value.promotion_projection_bytes.len() > MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1
    {
        return Err(ReplayRetentionBaselineWireError::Invalid);
    }
    let mut output = Vec::with_capacity(
        value
            .promotion_projection_bytes
            .len()
            .checked_add(640)
            .ok_or(ReplayRetentionBaselineWireError::Invalid)?,
    );
    for field in [
        &value.schema_version.to_be_bytes()[..],
        &value.authority_id,
        value.principal_id.as_bytes(),
        &value.lineage_id,
        &value.runtime_session_binding_digest,
        &value.replay_scope_digest,
        &[v2_kind_code(value.aggregate_kind)][..],
        &value.aggregate_id,
        &value.sequence.to_be_bytes()[..],
        &value.version.to_be_bytes()[..],
        &value.baseline_global_position.to_be_bytes()[..],
        &value.head_event_id,
        &value.head_integrity_digest,
        &[value.promotion_codec][..],
        &value.promotion_projection_bytes,
        &value.promotion_projection_digest,
        &value.retained_floor.to_be_bytes()[..],
        &value.captured_high_water.to_be_bytes()[..],
        &value.retention_generation.to_be_bytes()[..],
        &value.retention_manifest_digest,
        &value.issued_at_unix_ms.to_be_bytes()[..],
        &value.expires_at_unix_ms.to_be_bytes()[..],
    ] {
        output.extend_from_slice(
            &u32::try_from(field.len())
                .map_err(|_| ReplayRetentionBaselineWireError::Invalid)?
                .to_be_bytes(),
        );
        output.extend_from_slice(field);
    }
    Ok(output)
}

const fn v2_kind_code(kind: ApiReplayAggregateKind) -> u8 {
    match kind {
        ApiReplayAggregateKind::TaskRun => 1,
        ApiReplayAggregateKind::Conversation => 2,
    }
}
