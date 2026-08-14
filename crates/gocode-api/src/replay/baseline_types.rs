/// Unauthenticated replay-retention baseline wire claims.
///
/// Parsed transport values remain untrusted until the runtime client verifies
/// their session-bound MAC. This type deliberately has no serde implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct ReplayRetentionBaselineWireV1 {
    fields: UnauthenticatedReplayRetentionBaselineFieldsV1,
}

/// Exact parsed baseline fields for a transport adapter. Construction does not
/// validate, authenticate, or restore an aggregate.
#[derive(Clone, Eq, PartialEq)]
pub struct UnauthenticatedReplayRetentionBaselineFieldsV1 {
    pub schema_version: u8,
    pub authority_id: [u8; 16],
    pub principal_id: String,
    pub lineage_id: [u8; 16],
    pub runtime_session_binding_digest: [u8; 32],
    pub replay_scope_digest: [u8; 32],
    pub aggregate_kind: ApiReplayAggregateKind,
    pub aggregate_id: [u8; 16],
    pub sequence: u64,
    pub version: u64,
    pub baseline_global_position: i64,
    pub projection_codec: u8,
    pub projection_bytes: Vec<u8>,
    pub projection_digest: [u8; 32],
    pub retained_floor: i64,
    pub captured_high_water: i64,
    pub retention_generation: u64,
    pub retention_witness: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub witness_mac: [u8; 32],
}

impl ReplayRetentionBaselineWireV1 {
    /// Wraps parsed fields without granting authenticity.
    pub fn from_unauthenticated_fields(
        value: UnauthenticatedReplayRetentionBaselineFieldsV1,
    ) -> Self {
        Self { fields: value }
    }
    /// Returns an exact unauthenticated transport view.
    pub fn to_unauthenticated_fields(&self) -> UnauthenticatedReplayRetentionBaselineFieldsV1 {
        self.fields.clone()
    }
}

impl std::fmt::Debug for ReplayRetentionBaselineWireV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayRetentionBaselineWireV1")
            .field("schema_version", &self.fields.schema_version)
            .field("aggregate_kind", &self.fields.aggregate_kind)
            .field("redacted", &true)
            .finish()
    }
}

/// Structural failure of untrusted baseline claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayRetentionBaselineWireError {
    Invalid,
}

/// Validates only structural claim consistency and decodes the closed raw
/// projection. It never authenticates or promotes a baseline.
pub fn validate_unauthenticated_replay_retention_baseline(
    wire: &ReplayRetentionBaselineWireV1,
    expected_kind: ApiReplayAggregateKind,
    expected_aggregate_id: &[u8; 16],
) -> Result<UnauthenticatedReplayProjectionV1, ReplayRetentionBaselineWireError> {
    let value = &wire.fields;
    if value.schema_version != 1
        || value.sequence == 0
        || value.sequence != value.version
        || value.baseline_global_position <= 0
        || value.retained_floor <= 0
        || value.baseline_global_position > value.captured_high_water
        || value.retained_floor > value.captured_high_water
        || value.retention_generation == 0
        || value.retention_witness == [0; 32]
        || value.projection_codec != 1
        || value.expires_at_unix_ms <= value.issued_at_unix_ms
        || value
            .expires_at_unix_ms
            .saturating_sub(value.issued_at_unix_ms)
            > 30_000
    {
        return Err(ReplayRetentionBaselineWireError::Invalid);
    }
    if value.aggregate_kind != expected_kind || value.aggregate_id != *expected_aggregate_id {
        return Err(ReplayRetentionBaselineWireError::Invalid);
    }
    let projection = match expected_kind {
        ApiReplayAggregateKind::Conversation => {
            UnauthenticatedReplayProjectionV1::decode_conversation_bytes(&value.projection_bytes)
        }
        ApiReplayAggregateKind::TaskRun => {
            UnauthenticatedReplayProjectionV1::decode_task_run_bytes(&value.projection_bytes)
        }
    }
    .map_err(|_| ReplayRetentionBaselineWireError::Invalid)?;
    if projection.aggregate_id() != value.aggregate_id
        || projection.projection_digest() != &value.projection_digest
    {
        return Err(ReplayRetentionBaselineWireError::Invalid);
    }
    Ok(projection)
}

/// Computes the canonical digest for one public aggregate replay scope.
#[must_use]
pub fn canonical_aggregate_replay_scope_digest(
    aggregate_kind: ApiReplayAggregateKind,
    aggregate_id: &[u8; 16],
) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let aggregate_type = match aggregate_kind {
        ApiReplayAggregateKind::TaskRun => 1,
        ApiReplayAggregateKind::Conversation => 2,
    };
    let mut hasher = Sha256::new();
    hasher.update(1_u32.to_be_bytes());
    hasher.update([0, aggregate_type]);
    hasher.update(aggregate_id);
    hasher.finalize().into()
}
