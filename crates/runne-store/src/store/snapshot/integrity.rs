use sha2::{Digest, Sha256};

/// Hashes all durable snapshot bindings with explicit, unambiguous framing.
#[allow(clippy::too_many_arguments)] // Every argument is a distinct persisted transcript field.
pub(super) fn snapshot_integrity_digest(
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    aggregate_version: u64,
    event_sequence: u64,
    head_event_id: &[u8; 16],
    head_integrity_digest: &[u8; 32],
    head_global_position: i64,
    projection_digest: &[u8; 32],
    projection_bytes: &[u8],
    promotion_projection_digest: &[u8; 32],
    promotion_projection_bytes: &[u8],
) -> Option<[u8; 32]> {
    let aggregate_type = u8::try_from(aggregate_type).ok()?;
    let head_global_position = u64::try_from(head_global_position).ok()?;
    let projection_length = u64::try_from(projection_bytes.len()).ok()?;
    let promotion_projection_length = u64::try_from(promotion_projection_bytes.len()).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(b"gocode.store.aggregate-state-snapshot");
    hasher.update([0, 2]);
    frame(&mut hasher, &[1]); // codec_version
    frame(&mut hasher, &[aggregate_type]);
    frame(&mut hasher, aggregate_id);
    frame(&mut hasher, &aggregate_version.to_be_bytes());
    frame(&mut hasher, &event_sequence.to_be_bytes());
    frame(&mut hasher, head_event_id);
    frame(&mut hasher, head_integrity_digest);
    frame(&mut hasher, &head_global_position.to_be_bytes());
    frame(&mut hasher, projection_digest);
    frame(&mut hasher, &projection_length.to_be_bytes());
    frame(&mut hasher, projection_bytes);
    frame(&mut hasher, &[1]); // promotion_codec_version
    frame(&mut hasher, promotion_projection_digest);
    frame(&mut hasher, &promotion_projection_length.to_be_bytes());
    frame(&mut hasher, promotion_projection_bytes);
    Some(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn snapshot_integrity_digest_v1(
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    aggregate_version: u64,
    event_sequence: u64,
    head_event_id: &[u8; 16],
    head_integrity_digest: &[u8; 32],
    head_global_position: i64,
    projection_digest: &[u8; 32],
    projection_bytes: &[u8],
) -> Option<[u8; 32]> {
    let aggregate_type = u8::try_from(aggregate_type).ok()?;
    let head_global_position = u64::try_from(head_global_position).ok()?;
    let projection_length = u64::try_from(projection_bytes.len()).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(b"gocode.store.aggregate-state-snapshot");
    hasher.update([0, 1]);
    frame(&mut hasher, &[1]);
    frame(&mut hasher, &[aggregate_type]);
    frame(&mut hasher, aggregate_id);
    frame(&mut hasher, &aggregate_version.to_be_bytes());
    frame(&mut hasher, &event_sequence.to_be_bytes());
    frame(&mut hasher, head_event_id);
    frame(&mut hasher, head_integrity_digest);
    frame(&mut hasher, &head_global_position.to_be_bytes());
    frame(&mut hasher, projection_digest);
    frame(&mut hasher, &projection_length.to_be_bytes());
    frame(&mut hasher, projection_bytes);
    Some(hasher.finalize().into())
}

fn frame(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}
