#[cfg(any(test, feature = "fixture-only"))]
use super::{InspectedCanonicalPayload, Payload};

#[cfg(any(test, feature = "fixture-only"))]
pub struct SnapshotParts {
    pub promotion: String,
    pub revision: u64,
    pub state: String,
    pub binding: crate::Digest,
    pub candidate: crate::Digest,
    pub effect_generation: u64,
    pub previous: crate::Digest,
    pub command: crate::Digest,
    pub domain: String,
}

#[cfg(any(test, feature = "fixture-only"))]
impl InspectedCanonicalPayload {
    #[must_use]
    pub fn snapshot_parts(&self) -> Option<SnapshotParts> {
        let Payload::Snapshot(value) = &self.payload else {
            return None;
        };
        Some(SnapshotParts {
            promotion: value.promotion_id.clone(),
            revision: value.revision,
            state: value.state.clone(),
            binding: value.candidate_binding_sha256.0,
            candidate: value.candidate_sha256.0,
            effect_generation: value.effect_generation,
            previous: value.previous_snapshot_sha256.0,
            command: value.command_fingerprint_sha256.0,
            domain: value.domain.clone(),
        })
    }
}
