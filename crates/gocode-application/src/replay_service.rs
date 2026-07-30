//! ReplayService — coordination durable replay с cursor-based progress.

use std::sync::Arc;

use async_trait::async_trait;
use gocode_domain::event::Sensitivity;
use gocode_domain::id::{
    AggregateId, ConversationId, EventId, EventLogLineageId, IntegrityDigest, TaskRunId,
};
use gocode_domain::replay::{CURSOR_SCHEMA_VERSION, CatchUpCompletion, ReplayCursor, ReplayScope};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const MAX_EVENT_TYPE_BYTES: usize = 256;

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

/// Synchronous pre-commit check for the exact replay delivery a transport will
/// serialize. Implementations must fail closed when classification is
/// unavailable.
pub trait ReplayDeliveryPrecommitGuard: Send + Sync {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError>;
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
        server_secret: &[u8; 32],
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError>;

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
    ) -> Result<(), ReplayError>;

    async fn complete_catch_up(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        server_secret: &[u8; 32],
    ) -> Result<(ReplaySession, Option<ReplayEvent>), ReplayError>;

    async fn continue_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
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

/// Закрытый набор ошибок replay.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReplayError {
    #[error("session not found")]
    SessionNotFound,
    #[error("unauthorized: {0}")]
    Unauthorized(String),
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
    #[error("replay cursor precedes retained history")]
    RetentionGap,
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
    server_secret: [u8; 32],
    lineage_id: EventLogLineageId,
}

impl ReplayService {
    pub fn new(
        store: Arc<dyn ReplayStorePort>,
        server_secret: [u8; 32],
        lineage_id: EventLogLineageId,
    ) -> Self {
        Self {
            store,
            server_secret,
            lineage_id,
        }
    }

    fn cursor_message(cursor: &ReplayCursor) -> Result<Vec<u8>, ReplayError> {
        let event_type = cursor.event_type.as_bytes();
        if event_type.is_empty()
            || event_type.len() > MAX_EVENT_TYPE_BYTES
            || event_type.iter().any(|byte| byte.is_ascii_control())
        {
            return Err(ReplayError::CursorInvalid {
                reason: "invalid cursor event type".to_owned(),
            });
        }
        let event_type_len =
            u16::try_from(event_type.len()).map_err(|_| ReplayError::CursorInvalid {
                reason: "invalid cursor event type".to_owned(),
            })?;
        let mut message =
            Vec::with_capacity(16 + 1 + 16 + 8 + 8 + 16 + 32 + 4 + 1 + 2 + event_type.len());
        message.extend_from_slice(cursor.event_id.as_bytes());
        message.push(match &cursor.aggregate_id {
            AggregateId::TaskRun(_) => 1,
            AggregateId::Conversation(_) => 2,
            AggregateId::Workspace(_) => 3,
        });
        match &cursor.aggregate_id {
            AggregateId::TaskRun(id) => message.extend_from_slice(id.as_bytes()),
            AggregateId::Conversation(id) => message.extend_from_slice(id.as_bytes()),
            AggregateId::Workspace(id) => message.extend_from_slice(id.as_bytes()),
        }
        message.extend_from_slice(&cursor.sequence.to_be_bytes());
        message.extend_from_slice(&cursor.global_position.to_be_bytes());
        message.extend_from_slice(cursor.lineage_id.as_bytes());
        message.extend_from_slice(&cursor.scope.canonical_digest());
        message.extend_from_slice(&cursor.schema_version.to_be_bytes());
        message.push(match cursor.sensitivity {
            Sensitivity::Public => 0,
            Sensitivity::Internal => 1,
            Sensitivity::Sensitive => 2,
        });
        message.extend_from_slice(&event_type_len.to_be_bytes());
        message.extend_from_slice(event_type);
        Ok(message)
    }

    /// Строит ackable cursor из delivered event и границ session.
    fn build_cursor(
        &self,
        event: &ReplayEvent,
        scope: &ReplayScope,
    ) -> Result<ReplayCursor, ReplayError> {
        if event.global_position <= 0
            || event.sequence <= 0
            || event.schema_version == 0
            || event.event_type.is_empty()
            || event.event_type.len() > MAX_EVENT_TYPE_BYTES
            || event
                .event_type
                .as_bytes()
                .iter()
                .any(|byte| byte.is_ascii_control())
            || !matches!(
                scope,
                ReplayScope::Aggregate {
                    aggregate_type,
                    aggregate_id,
                } if i32::from(*aggregate_type) == event.aggregate_type
                    && aggregate_id == &event.aggregate_id
            )
        {
            return Err(ReplayError::Integrity(
                "invalid delivered replay event metadata".to_owned(),
            ));
        }
        let aggregate_id = match event.aggregate_type {
            1 => AggregateId::TaskRun(TaskRunId::from_bytes(event.aggregate_id)),
            2 => AggregateId::Conversation(ConversationId::from_bytes(event.aggregate_id)),
            _ => {
                return Err(ReplayError::Integrity(
                    "unsupported delivered replay aggregate".to_owned(),
                ));
            }
        };
        let sensitivity = match event.sensitivity {
            0 => Sensitivity::Public,
            1 => Sensitivity::Internal,
            2 => Sensitivity::Sensitive,
            _ => {
                return Err(ReplayError::Integrity(
                    "invalid delivered replay sensitivity".to_owned(),
                ));
            }
        };
        let mut cursor = ReplayCursor {
            event_id: EventId::from_bytes(event.event_id),
            aggregate_id,
            sequence: u64::try_from(event.sequence).map_err(|_| {
                ReplayError::Integrity("invalid delivered replay sequence".to_owned())
            })?,
            global_position: event.global_position,
            lineage_id: self.lineage_id,
            scope: scope.clone(),
            schema_version: CURSOR_SCHEMA_VERSION,
            sensitivity,
            event_type: event.event_type.clone(),
            integrity: IntegrityDigest::from_bytes([0; 32]),
        };
        let mut mac = HmacSha256::new_from_slice(&self.server_secret).expect("fixed HMAC key size");
        mac.update(&Self::cursor_message(&cursor)?);
        cursor.integrity = IntegrityDigest::from_bytes(mac.finalize().into_bytes().into());
        Ok(cursor)
    }

    /// Проверяет integrity cursor относительно server secret.
    pub fn validate_cursor_integrity(&self, cursor: &ReplayCursor) -> Result<(), ReplayError> {
        if cursor.schema_version != CURSOR_SCHEMA_VERSION {
            return Err(ReplayError::CursorInvalid {
                reason: "unsupported cursor schema".to_string(),
            });
        }
        if cursor.lineage_id != self.lineage_id {
            return Err(ReplayError::CursorInvalid {
                reason: "event log lineage mismatch".to_string(),
            });
        }
        let mut mac = HmacSha256::new_from_slice(&self.server_secret).expect("fixed HMAC key size");
        mac.update(&Self::cursor_message(cursor)?);
        mac.verify_slice(cursor.integrity.as_bytes())
            .map_err(|_| ReplayError::CursorInvalid {
                reason: "cursor integrity mismatch".to_string(),
            })
    }

    /// Публичный helper для transport adapter, формирующий cursor delivered event.
    pub fn build_cursor_from_event(
        &self,
        event: &ReplayEvent,
        scope: &ReplayScope,
    ) -> Result<ReplayCursor, ReplayError> {
        self.build_cursor(event, scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open_session(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
        from_cursor: Option<ReplayCursor>,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        if let Some(cursor) = &from_cursor {
            self.validate_cursor_integrity(cursor)?;
            if !matches!(
                &cursor.scope,
                ReplayScope::Aggregate { aggregate_type: cursor_type, aggregate_id: cursor_id }
                    if i32::from(*cursor_type) == aggregate_type && cursor_id == aggregate_id
            ) {
                return Err(ReplayError::CursorInvalid {
                    reason: "cursor scope mismatch".to_string(),
                });
            }
        }
        self.store
            .open_session(
                principal_id,
                session_generation,
                authority_id,
                authorization_epoch,
                aggregate_type,
                aggregate_id,
                from_cursor.as_ref(),
                &self.server_secret,
                delivery_guard,
            )
            .await
    }

    /// Читает следующую страницу; cursor каждого event строится transport adapter через `build_cursor_from_event`.
    #[allow(clippy::too_many_arguments)]
    pub async fn read_page(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        limit: usize,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        self.store
            .read_page(
                session_id,
                principal_id,
                generation,
                authority_id,
                epoch,
                limit,
                delivery_guard,
            )
            .await
    }

    /// Подтверждает cursor после проверки его integrity на application boundary.
    pub async fn acknowledge(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        cursor: &ReplayCursor,
    ) -> Result<(), ReplayError> {
        self.validate_cursor_integrity(cursor)?;
        self.store
            .acknowledge(
                session_id,
                principal_id,
                generation,
                authority_id,
                epoch,
                cursor,
            )
            .await
    }

    /// Завершает catch-up и возвращает server-issued proof.
    pub async fn complete_catch_up(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<CatchUpCompletion, ReplayError> {
        let (session, last_ack_event) = self
            .store
            .complete_catch_up(
                session_id,
                principal_id,
                generation,
                authority_id,
                epoch,
                &self.server_secret,
            )
            .await?;
        let scope = ReplayScope::Aggregate {
            aggregate_type: u8::try_from(session.aggregate_type)
                .map_err(|_| ReplayError::Integrity("invalid completed replay scope".to_owned()))?,
            aggregate_id: session.aggregate_id,
        };
        let last_ack_cursor = last_ack_event
            .as_ref()
            .map(|event| self.build_cursor(event, &scope))
            .transpose()?;
        let proof = session.catch_up_completion.ok_or_else(|| {
            ReplayError::Integrity("missing catch-up completion proof".to_string())
        })?;
        if proof.len() != 32 {
            return Err(ReplayError::Integrity(
                "invalid catch-up completion proof length".to_string(),
            ));
        }
        let mut proof_bytes = [0; 32];
        proof_bytes.copy_from_slice(&proof);
        Ok(CatchUpCompletion {
            session_id: session.session_id,
            high_water_ref: session.high_water_ref,
            last_ack_cursor,
            proof: IntegrityDigest::from_bytes(proof_bytes),
        })
    }

    pub async fn continue_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<ReplaySession, ReplayError> {
        self.store
            .continue_live(session_id, principal_id, generation, authority_id, epoch)
            .await
    }

    pub async fn poll_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        self.store
            .poll_live(
                session_id,
                principal_id,
                generation,
                authority_id,
                epoch,
                delivery_guard,
            )
            .await
    }

    pub async fn close_session(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<(), ReplayError> {
        self.store
            .close_session(session_id, principal_id, generation, authority_id, epoch)
            .await
    }
}
