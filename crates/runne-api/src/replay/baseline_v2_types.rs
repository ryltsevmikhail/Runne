use runne_domain::id::validate_uuid_v7_bytes;

/// Maximum decoded V2 promotion projection size.
pub const MAX_REPLAY_PROMOTION_PROJECTION_BYTES: usize = 512 * 1024;
/// Maximum unpadded base64url length of a bounded V2 promotion projection.
pub const MAX_REPLAY_PROMOTION_PROJECTION_BASE64URL_CHARS: usize =
    (MAX_REPLAY_PROMOTION_PROJECTION_BYTES / 3) * 4
        + match MAX_REPLAY_PROMOTION_PROJECTION_BYTES % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        };

/// Unauthenticated signed V2 baseline claims used only to resume an anchored
/// shadow replay. Parsing this type does not authenticate or promote state.
#[derive(Clone, Eq, PartialEq)]
pub struct ReplayRetentionBaselineWireV2 {
    fields: UnauthenticatedReplayRetentionBaselineFieldsV2,
}

/// Exact V2 transport fields. They remain untrusted until the session authority
/// verifies `witness_mac` over the V2 transcript.
#[derive(Clone, Eq, PartialEq)]
pub struct UnauthenticatedReplayRetentionBaselineFieldsV2 {
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
    pub head_event_id: [u8; 16],
    pub head_integrity_digest: [u8; 32],
    pub promotion_codec: u8,
    pub promotion_projection_bytes: Vec<u8>,
    pub promotion_projection_digest: [u8; 32],
    pub retained_floor: i64,
    pub captured_high_water: i64,
    pub retention_generation: u64,
    pub retention_manifest_digest: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub witness_mac: [u8; 32],
}

impl ReplayRetentionBaselineWireV2 {
    /// Wraps parsed transport fields without granting authenticity.
    pub fn from_unauthenticated_fields(
        value: UnauthenticatedReplayRetentionBaselineFieldsV2,
    ) -> Self {
        Self { fields: value }
    }

    /// Returns an exact unauthenticated view for transport and server adapters.
    pub fn to_unauthenticated_fields(&self) -> UnauthenticatedReplayRetentionBaselineFieldsV2 {
        self.fields.clone()
    }

    pub(crate) const fn unauthenticated_fields(
        &self,
    ) -> &UnauthenticatedReplayRetentionBaselineFieldsV2 {
        &self.fields
    }
}

impl std::fmt::Debug for ReplayRetentionBaselineWireV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayRetentionBaselineWireV2")
            .field("schema_version", &self.fields.schema_version)
            .field("aggregate_kind", &self.fields.aggregate_kind)
            .field("redacted", &true)
            .finish()
    }
}

/// Validates V2 claim shape and promotion bytes only. It intentionally does
/// not authenticate the witness, authorize a principal, or promote an aggregate.
pub fn validate_unauthenticated_replay_retention_baseline_v2(
    wire: &ReplayRetentionBaselineWireV2,
    expected_kind: ApiReplayAggregateKind,
    expected_aggregate_id: &[u8; 16],
) -> Result<UnauthenticatedReplayPromotionProjectionV1, ReplayRetentionBaselineWireError> {
    let value = &wire.fields;
    if value.schema_version != 2
        || value.sequence == 0
        || value.sequence != value.version
        || value.baseline_global_position <= 0
        || value.retained_floor <= 0
        || value.retained_floor > value.baseline_global_position
        || value.baseline_global_position > value.captured_high_water
        || value.retained_floor > value.captured_high_water
        || value.retention_generation == 0
        || value.head_integrity_digest == [0; 32]
        || value.retention_manifest_digest == [0; 32]
        || value.promotion_codec != 1
        || value.promotion_projection_bytes.len() > MAX_REPLAY_PROMOTION_PROJECTION_BYTES
        || value.expires_at_unix_ms <= value.issued_at_unix_ms
        || value
            .expires_at_unix_ms
            .saturating_sub(value.issued_at_unix_ms)
            > 30_000
        || validate_uuid_v7_bytes(&value.head_event_id).is_err()
        || value.aggregate_kind != expected_kind
        || value.aggregate_id != *expected_aggregate_id
    {
        return Err(ReplayRetentionBaselineWireError::Invalid);
    }
    let projection =
        crate::replay::promotion_projection::UnauthenticatedReplayPromotionProjectionV1::decode(
            &value.promotion_projection_bytes,
        )
        .map_err(|_| ReplayRetentionBaselineWireError::Invalid)?;
    let (kind, id, digest) = match projection.view() {
        crate::replay::promotion_projection::ReplayPromotionProjectionViewV1::Conversation(
            view,
        ) => (
            ApiReplayAggregateKind::Conversation,
            view.aggregate_id(),
            view.projection_digest(),
        ),
        crate::replay::promotion_projection::ReplayPromotionProjectionViewV1::TaskRun(view) => (
            ApiReplayAggregateKind::TaskRun,
            view.aggregate_id(),
            view.closed_snapshot_digest(),
        ),
    };
    if kind != value.aggregate_kind
        || id != value.aggregate_id
        || digest != &value.promotion_projection_digest
    {
        return Err(ReplayRetentionBaselineWireError::Invalid);
    }
    Ok(projection)
}
