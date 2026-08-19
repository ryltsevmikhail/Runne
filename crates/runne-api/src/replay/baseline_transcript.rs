/// Canonical domain separation used before deriving a session-bound baseline key.
pub const REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V1: &[u8] =
    b"runne.replay-retention-baseline.key.v1\0";

/// Returns the exact length-framed unauthenticated baseline claim transcript.
pub fn replay_retention_baseline_transcript(wire: &ReplayRetentionBaselineWireV1) -> Vec<u8> {
    let value = wire.to_unauthenticated_fields();
    let mut output = Vec::with_capacity(value.projection_bytes.len().saturating_add(512));
    for field in [
        &value.schema_version.to_be_bytes()[..],
        &value.authority_id,
        value.principal_id.as_bytes(),
        &value.lineage_id,
        &value.runtime_session_binding_digest,
        &value.replay_scope_digest,
        &[kind_code(value.aggregate_kind)][..],
        &value.aggregate_id,
        &value.sequence.to_be_bytes()[..],
        &value.version.to_be_bytes()[..],
        &value.baseline_global_position.to_be_bytes()[..],
        &[value.projection_codec][..],
        &value.projection_bytes,
        &value.projection_digest,
        &value.retained_floor.to_be_bytes()[..],
        &value.captured_high_water.to_be_bytes()[..],
        &value.retention_generation.to_be_bytes()[..],
        &value.retention_witness,
        &value.issued_at_unix_ms.to_be_bytes()[..],
        &value.expires_at_unix_ms.to_be_bytes()[..],
    ] {
        output.extend_from_slice(
            &u32::try_from(field.len())
                .expect("bounded baseline field")
                .to_be_bytes(),
        );
        output.extend_from_slice(field);
    }
    output
}
const fn kind_code(kind: ApiReplayAggregateKind) -> u8 {
    match kind {
        ApiReplayAggregateKind::TaskRun => 1,
        ApiReplayAggregateKind::Conversation => 2,
    }
}
