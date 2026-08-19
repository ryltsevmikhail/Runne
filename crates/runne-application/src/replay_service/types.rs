/// Состояние durable replay session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayState {
    CatchingUp,
    CatchUpComplete,
    ActivatingLive,
    Live,
    Closed,
}

impl ReplayState {
    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "catching_up" => Some(Self::CatchingUp),
            "catch_up_complete" => Some(Self::CatchUpComplete),
            "activating_live" => Some(Self::ActivatingLive),
            "live" => Some(Self::Live),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }

    pub fn as_db(&self) -> &'static str {
        match self {
            Self::CatchingUp => "catching_up",
            Self::CatchUpComplete => "catch_up_complete",
            Self::ActivatingLive => "activating_live",
            Self::Live => "live",
            Self::Closed => "closed",
        }
    }
}

/// Данные session из `_replay_subscriptions`.
#[derive(Clone, Debug)]
pub struct ReplaySession {
    pub session_id: [u8; 16],
    pub principal_id: String,
    pub session_generation: i64,
    pub authority_id: [u8; 16],
    pub authorization_epoch: i64,
    pub aggregate_type: i32,
    pub aggregate_id: [u8; 16],
    pub retained_floor: Option<i64>,
    pub retention_generation: i64,
    pub high_water_position: i64,
    pub next_page_position: Option<i64>,
    pub last_delivered_position: Option<i64>,
    pub last_acked_position: Option<i64>,
    pub state: ReplayState,
    pub high_water_ref: Vec<u8>,
    pub catch_up_completion: Option<Vec<u8>>,
    pub live_delivery_id: Option<Vec<u8>>,
    pub created_at: String,
}

/// Canonical event row delivered by replay.
#[derive(Clone, Debug)]
pub struct ReplayEvent {
    pub global_position: i64,
    pub event_id: [u8; 16],
    pub aggregate_type: i32,
    pub aggregate_id: [u8; 16],
    pub payload: Vec<u8>,
    pub timestamp: i64,
    pub event_type: String,
    /// Aggregate-local sequence.
    pub sequence: i64,
    /// 0=Public, 1=Internal, 2=Sensitive.
    pub sensitivity: i32,
    /// Event schema version.
    pub schema_version: u32,
    /// Optional causal predecessor.
    pub causation_id: Option<[u8; 16]>,
    /// Command that produced the event.
    pub command_id: [u8; 16],
    /// Opaque idempotency key bytes decoded as validated UTF-8.
    pub idempotency_key: String,
    /// Validated actor identity.
    pub actor: String,
    /// Stored event integrity digest.
    pub integrity_digest: [u8; 32],
    /// Correlation aggregate identity.
    pub correlation_id: [u8; 16],
    /// 1=TaskRun, 2=Conversation.
    pub correlation_type: i32,
    /// Stored integrity profile version.
    pub integrity_profile: i32,
}
