/// Semantic, storage-verified material that may be issued as a V2 resume
/// baseline only after session authorization.
#[derive(Clone)]
pub struct ReplayRetentionBaselineCandidateV2 {
    promotion_projection: gocode_api::UnauthenticatedReplayPromotionProjectionV1,
    promotion_projection_bytes: Vec<u8>,
    sequence: u64,
    version: u64,
    baseline_global_position: i64,
    head_event_id: [u8; 16],
    head_integrity_digest: [u8; 32],
    retained_floor: i64,
    captured_high_water: i64,
    retention_generation: u64,
    retention_manifest_digest: [u8; 32],
}

impl std::fmt::Debug for ReplayRetentionBaselineCandidateV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplayRetentionBaselineCandidateV2")
            .field("sequence", &self.sequence)
            .field("redacted", &true)
            .finish()
    }
}

/// Storage facts from which a V2 baseline candidate is validated.
pub struct ReplayRetentionBaselineCandidateV2Parts {
    pub promotion_projection_bytes: Vec<u8>,
    pub sequence: u64,
    pub version: u64,
    pub baseline_global_position: i64,
    pub head_event_id: [u8; 16],
    pub head_integrity_digest: [u8; 32],
    pub retained_floor: i64,
    pub captured_high_water: i64,
    pub retention_generation: u64,
    pub retention_manifest_digest: [u8; 32],
}

/// The durable material cannot form an internally consistent V2 baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayRetentionBaselineCandidateV2Error {
    Invalid,
}

impl ReplayRetentionBaselineCandidateV2 {
    /// Parses complete promotion bytes and accepts only internally consistent
    /// baseline facts; caller identity and authorization remain session-owned.
    pub fn from_storage(
        parts: ReplayRetentionBaselineCandidateV2Parts,
    ) -> Result<Self, ReplayRetentionBaselineCandidateV2Error> {
        let promotion_projection = gocode_api::UnauthenticatedReplayPromotionProjectionV1::decode(
            &parts.promotion_projection_bytes,
        )
        .map_err(|_| ReplayRetentionBaselineCandidateV2Error::Invalid)?;
        if parts.sequence == 0
            || parts.sequence != parts.version
            || parts.baseline_global_position <= 0
            || parts.retained_floor <= 0
            || parts.baseline_global_position > parts.captured_high_water
            || parts.retained_floor > parts.baseline_global_position
            || parts.retained_floor > parts.captured_high_water
            || parts.retention_generation == 0
            || parts.head_integrity_digest == [0; 32]
            || parts.retention_manifest_digest == [0; 32]
        {
            return Err(ReplayRetentionBaselineCandidateV2Error::Invalid);
        }
        Ok(Self {
            promotion_projection,
            promotion_projection_bytes: parts.promotion_projection_bytes,
            sequence: parts.sequence,
            version: parts.version,
            baseline_global_position: parts.baseline_global_position,
            head_event_id: parts.head_event_id,
            head_integrity_digest: parts.head_integrity_digest,
            retained_floor: parts.retained_floor,
            captured_high_water: parts.captured_high_water,
            retention_generation: parts.retention_generation,
            retention_manifest_digest: parts.retention_manifest_digest,
        })
    }

    pub(crate) const fn promotion_projection(
        &self,
    ) -> &gocode_api::UnauthenticatedReplayPromotionProjectionV1 {
        &self.promotion_projection
    }
    pub(crate) fn promotion_projection_bytes(&self) -> &[u8] {
        &self.promotion_projection_bytes
    }
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) const fn version(&self) -> u64 {
        self.version
    }
    pub(crate) const fn baseline_global_position(&self) -> i64 {
        self.baseline_global_position
    }
    pub(crate) const fn head_event_id(&self) -> [u8; 16] {
        self.head_event_id
    }
    pub(crate) const fn head_integrity_digest(&self) -> [u8; 32] {
        self.head_integrity_digest
    }
    pub(crate) const fn retained_floor(&self) -> i64 {
        self.retained_floor
    }
    pub(crate) const fn captured_high_water(&self) -> i64 {
        self.captured_high_water
    }
    pub(crate) const fn retention_generation(&self) -> u64 {
        self.retention_generation
    }
    pub(crate) const fn retention_manifest_digest(&self) -> [u8; 32] {
        self.retention_manifest_digest
    }
}

/// Closed V2 resume admission material.  Only this crate can construct it;
/// adapters may inspect the semantic facts needed to re-validate durable state.
///
/// ```compile_fail
/// use gocode_application::ports::ReplayBaselineResumeRequestV2;
/// let _ = ReplayBaselineResumeRequestV2::new();
/// ```
pub struct ReplayBaselineResumeRequestV2 {
    principal_id: String,
    session_generation: i64,
    authority_id: [u8; 16],
    authorization_epoch: i64,
    aggregate_type: i32,
    aggregate_id: [u8; 16],
    sequence: u64,
    version: u64,
    baseline_global_position: i64,
    head_event_id: [u8; 16],
    head_integrity_digest: [u8; 32],
    promotion_projection_bytes: Vec<u8>,
    promotion_projection_digest: [u8; 32],
    retained_floor: i64,
    captured_high_water: i64,
    retention_generation: u64,
    retention_manifest_digest: [u8; 32],
}

impl ReplayBaselineResumeRequestV2 {
    pub(crate) fn from_authenticated(
        principal_id: &str,
        session_generation: i64,
        authority_id: [u8; 16],
        authorization_epoch: i64,
        claims: crate::local_session::AuthenticatedReplayBaselineResumeV2,
    ) -> Self {
        Self {
            principal_id: principal_id.to_owned(),
            session_generation,
            authority_id,
            authorization_epoch,
            aggregate_type: match claims.aggregate_kind() {
                gocode_api::ApiReplayAggregateKind::TaskRun => 1,
                gocode_api::ApiReplayAggregateKind::Conversation => 2,
            },
            aggregate_id: claims.aggregate_id(),
            sequence: claims.sequence(),
            version: claims.version(),
            baseline_global_position: claims.baseline_global_position(),
            head_event_id: claims.head_event_id(),
            head_integrity_digest: claims.head_integrity_digest(),
            promotion_projection_bytes: claims.promotion_projection_bytes().to_vec(),
            promotion_projection_digest: claims.promotion_projection_digest(),
            retained_floor: claims.retained_floor(),
            captured_high_water: claims.captured_high_water(),
            retention_generation: claims.retention_generation(),
            retention_manifest_digest: claims.retention_manifest_digest(),
        }
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }
    pub const fn session_generation(&self) -> i64 {
        self.session_generation
    }
    pub const fn authority_id(&self) -> &[u8; 16] {
        &self.authority_id
    }
    pub const fn authorization_epoch(&self) -> i64 {
        self.authorization_epoch
    }
    pub const fn aggregate_type(&self) -> i32 {
        self.aggregate_type
    }
    pub const fn aggregate_id(&self) -> &[u8; 16] {
        &self.aggregate_id
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn version(&self) -> u64 {
        self.version
    }
    pub const fn baseline_global_position(&self) -> i64 {
        self.baseline_global_position
    }
    pub const fn head_event_id(&self) -> &[u8; 16] {
        &self.head_event_id
    }
    pub const fn head_integrity_digest(&self) -> &[u8; 32] {
        &self.head_integrity_digest
    }
    pub fn promotion_projection_bytes(&self) -> &[u8] {
        &self.promotion_projection_bytes
    }
    pub const fn promotion_projection_digest(&self) -> &[u8; 32] {
        &self.promotion_projection_digest
    }
    pub const fn retained_floor(&self) -> i64 {
        self.retained_floor
    }
    pub const fn captured_high_water(&self) -> i64 {
        self.captured_high_water
    }
    pub const fn retention_generation(&self) -> u64 {
        self.retention_generation
    }
    pub const fn retention_manifest_digest(&self) -> &[u8; 32] {
        &self.retention_manifest_digest
    }
}
