use runne_domain::id::{IntegrityDigest, PlanEvaluationId};
use sha2::{Digest, Sha256};

pub(super) fn hash(bytes: &[u8]) -> IntegrityDigest {
    IntegrityDigest::from_bytes(Sha256::digest(bytes).into())
}

pub(super) fn deterministic_evaluation_id(
    timestamp_us: i64,
    digest: IntegrityDigest,
) -> PlanEvaluationId {
    let mut bytes = [0; 16];
    let millis = u64::try_from(timestamp_us.max(0) / 1_000).unwrap_or(0);
    bytes[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
    bytes[6..].copy_from_slice(&digest.as_bytes()[..10]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    PlanEvaluationId::from_bytes(bytes)
}
