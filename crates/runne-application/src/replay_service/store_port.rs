/// Complete storage-verified material which must be authenticated by the
/// application before it is disclosed outside the replay boundary.
#[derive(Clone, Debug)]
pub struct ReplayRetentionBaselineCandidateV1 {
    pub projection: runne_api::UnauthenticatedReplayProjectionV1,
    pub sequence: u64,
    pub version: u64,
    pub baseline_global_position: i64,
    pub retained_floor: i64,
    pub captured_high_water: i64,
    pub retention_generation: u64,
    pub retention_witness: [u8; 32],
}

/// Store result which keeps retained floor material internal until the
/// application has applied the current sensitivity lease.
#[derive(Clone, Debug)]
pub enum ReplayOpenResult {
    Opened {
        session: ReplaySession,
        events: Vec<ReplayEvent>,
    },
    RetentionGap {
        baseline: ReplayRetentionBaselineCandidateV1,
    },
    RetentionGapWithV2 {
        baseline: ReplayRetentionBaselineCandidateV1,
        baseline_v2: Box<ReplayRetentionBaselineCandidateV2>,
    },
}

impl ReplayOpenResult {
    pub fn into_opened(self) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        match self {
            Self::Opened { session, events } => Ok((session, events)),
            Self::RetentionGap { .. } | Self::RetentionGapWithV2 { .. } => {
                Err(ReplayError::Integrity(
                    "retention baseline requires authenticated issuance".to_owned(),
                ))
            }
        }
    }
}

/// Durable storage port for replay sessions.
#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait ReplayStorePort: Send + Sync {
    async fn resume_session_from_baseline_v2(
        &self,
        _request: ReplayBaselineResumeRequestV2,
        _lineage_id: &EventLogLineageId,
        _server_secret: &[u8; 32],
        _delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>, ReplayEvent, ReplayAcceptedPromotionV2), ReplayError> {
        Err(ReplayError::Integrity(
            "V2 replay resume is unavailable".to_owned(),
        ))
    }

    /// Resolves one open session's delivery scope for delivery-time trust
    /// re-checks (NM-06). `Ok(None)` marks an unknown session (callers fall
    /// through to the store's own handling); `Err` is a storage failure and
    /// must fail closed — never treated as absence.
    fn session_delivery_scope(
        &self,
        _session_id: &[u8; 16],
    ) -> Result<Option<(i32, [u8; 16])>, ReplayError> {
        Ok(None)
    }

    async fn open_session(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
        from_cursor: Option<&ReplayCursor>,
        lineage_id: &EventLogLineageId,
        server_secret: &[u8; 32],
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplayOpenResult, ReplayError>;

    async fn retention_manifest(
        &self,
        lineage_id: &EventLogLineageId,
        server_secret: &[u8; 32],
    ) -> Result<RetentionManifest, ReplayError>;

    async fn read_page(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        limit: usize,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError>;

    async fn acknowledge(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        cursor: &ReplayCursor,
        authorization_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(), ReplayError>;

    async fn complete_catch_up(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        server_secret: &[u8; 32],
        authorization_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Option<ReplayEvent>), ReplayError>;

    async fn continue_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        authorization_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplaySession, ReplayError>;

    async fn poll_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError>;

    async fn close_session(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<(), ReplayError>;
}
