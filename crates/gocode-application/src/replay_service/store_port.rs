/// Store result which keeps retained floor material internal until the
/// application has applied the current sensitivity lease.
#[derive(Clone, Debug)]
pub enum ReplayOpenResult {
    Opened {
        session: ReplaySession,
        events: Vec<ReplayEvent>,
    },
    RetentionGap {
        floor_event: Option<ReplayEvent>,
        gap_range_ref: GapRangeRef,
    },
}

impl ReplayOpenResult {
    pub fn into_opened(self) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        match self {
            Self::Opened { session, events } => Ok((session, events)),
            Self::RetentionGap { gap_range_ref, .. } => Err(ReplayError::ReplayRetentionGap {
                floor_cursor: None,
                gap_range_ref,
            }),
        }
    }
}

/// Durable storage port for replay sessions.
#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait ReplayStorePort: Send + Sync {
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
