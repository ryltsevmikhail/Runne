/// Закрытый набор ошибок replay.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReplayError {
    #[error("session not found")]
    SessionNotFound,
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("replay authorization was revoked")]
    AuthorizationRevoked,
    #[error("invalid state transition from {0}")]
    InvalidState(String),
    #[error("stale generation")]
    StaleGeneration,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("integrity error: {0}")]
    Integrity(String),
    #[error("invalid cursor: {reason}")]
    CursorInvalid { reason: String },
    #[error("event sensitivity is not permitted")]
    SensitivityDenied,
    #[error("replay cursor crosses unavailable retained history")]
    ReplayRetentionGap {
        baseline: Box<runne_api::ReplayRetentionBaselineWireV1>,
    },
    #[error("replay cursor crosses unavailable retained history")]
    ReplayRetentionGapV2 {
        baseline: Box<runne_api::ReplayRetentionBaselineWireV2>,
    },
    #[error("delivered events have not been acknowledged")]
    NotAcknowledged,
    #[error("cursor was already acknowledged")]
    AlreadyAcknowledged,
    #[error("stream terminated")]
    StreamTerminated,
    #[error("delivery backpressure exceeded")]
    BackpressureExceeded,
}

/// Координатор cursor-based durable replay.
pub struct ReplayService {
    store: Arc<dyn ReplayStorePort>,
    authorization: Arc<dyn ReplayAuthorizationPort>,
    server_secret: [u8; 32],
    lineage_id: EventLogLineageId,
}

struct AuthorizedDeliveryGuard {
    authorization: Arc<dyn ReplayAuthorizationPort>,
    request: ReplayAuthorizationRequest,
    lease: ReplayAuthorizationLease,
    delegate: Arc<dyn ReplayDeliveryPrecommitGuard>,
}
