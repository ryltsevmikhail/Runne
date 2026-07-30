//! ReplayService — coordination durable replay с cursor-based progress.

use std::sync::Arc;

use async_trait::async_trait;
use gocode_api::CanonicalReplayPayloadV1;
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::event::Sensitivity;
use gocode_domain::id::{
    AggregateId, ConversationId, EventId, EventLogLineageId, IntegrityDigest, TaskRunId,
};
use gocode_domain::replay::{CURSOR_SCHEMA_VERSION, CatchUpCompletion, ReplayCursor, ReplayScope};
use gocode_domain::replay::{GapRangeRef, RetentionManifest};
use gocode_domain::task_run::TaskRunEvent;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const MAX_EVENT_TYPE_BYTES: usize = 256;
pub const REPLAY_FRAME_CAPACITY_BYTES: usize = 256 * 1024;
pub const REPLAY_PAGE_CAPACITY_BYTES: usize = 1024 * 1024;
pub const REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES: usize = 32 * 1024;
pub const REPLAY_CANONICAL_EVENT_MAX_BYTES: usize =
    REPLAY_FRAME_CAPACITY_BYTES - REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES;

/// Rejects an exact canonical event that the current writer policy cannot
/// guarantee every configured replay reader can deliver.
pub fn validate_replay_writer_event_size(actual_bytes: usize) -> Result<(), ReplayError> {
    if actual_bytes > REPLAY_CANONICAL_EVENT_MAX_BYTES {
        return Err(ReplayError::Integrity(format!(
            "canonical replay event exceeds writer maximum: actual={actual_bytes}, \
             maximum={REPLAY_CANONICAL_EVENT_MAX_BYTES}"
        )));
    }
    Ok(())
}

/// Reader-first readiness gate for the larger of the active writer policy and
/// the largest retained canonical event.
pub fn validate_replay_reader_capacity(
    manifest: &RetentionManifest,
    frame_capacity_bytes: usize,
    page_capacity_bytes: usize,
    declared_overhead_bytes: usize,
) -> Result<(), ReplayError> {
    let required = manifest
        .maximum_encoded_event_bytes()
        .max(REPLAY_CANONICAL_EVENT_MAX_BYTES)
        .checked_add(declared_overhead_bytes)
        .ok_or_else(|| ReplayError::Integrity("replay capacity calculation overflow".to_owned()))?;
    if required > frame_capacity_bytes || required > page_capacity_bytes {
        return Err(ReplayError::Integrity(format!(
            "replay reader capacity insufficient: required={required}, \
             frame={frame_capacity_bytes}, page={page_capacity_bytes}"
        )));
    }
    Ok(())
}

/// Encoded canonical event metadata, excluding cursor and replay binding
/// wrappers which are admitted separately by the reader.
pub fn measured_conversation_replay_event_bytes(
    event: &ReplayEvent,
    payload: &ConversationEvent,
) -> Result<usize, ReplayError> {
    measured_canonical_replay_event_bytes(event, CanonicalReplayPayloadV1::from(payload))
}

/// Encoded canonical event metadata, excluding cursor and replay binding
/// wrappers which are admitted separately by the reader.
pub fn measured_taskrun_replay_event_bytes(
    event: &ReplayEvent,
    payload: &TaskRunEvent,
) -> Result<usize, ReplayError> {
    let payload = CanonicalReplayPayloadV1::try_from(payload)
        .map_err(|_| ReplayError::Integrity("invalid public TaskRun replay payload".to_owned()))?;
    measured_canonical_replay_event_bytes(event, payload)
}

fn measured_canonical_replay_event_bytes(
    event: &ReplayEvent,
    payload: CanonicalReplayPayloadV1,
) -> Result<usize, ReplayError> {
    let aggregate_type = match event.aggregate_type {
        1 => "taskRun",
        2 => "conversation",
        _ => {
            return Err(ReplayError::Integrity(
                "invalid canonical replay aggregate type".to_owned(),
            ));
        }
    };
    let correlation_type = match event.correlation_type {
        1 => "taskRun",
        2 => "conversation",
        _ => {
            return Err(ReplayError::Integrity(
                "invalid canonical replay correlation type".to_owned(),
            ));
        }
    };
    let sensitivity = match event.sensitivity {
        0 => "public",
        1 => "internal",
        2 => "sensitive",
        _ => {
            return Err(ReplayError::Integrity(
                "invalid canonical replay sensitivity".to_owned(),
            ));
        }
    };
    let payload = serde_json::to_value(payload)
        .map_err(|_| ReplayError::Integrity("encode canonical replay payload".to_owned()))?;
    let event_type = payload
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ReplayError::Integrity("canonical replay payload has no type".to_owned()))?;
    let uuid = |bytes: [u8; 16]| uuid::Uuid::from_bytes(bytes).to_string();
    let value = serde_json::json!({
        "aggregateId": uuid(event.aggregate_id),
        "aggregateType": aggregate_type,
        "causationEventId": event.causation_id.map(uuid),
        "correlationId": uuid(event.correlation_id),
        "correlationType": correlation_type,
        "eventId": uuid(event.event_id),
        "eventType": event_type,
        "integrityDigest": lower_hex(&event.integrity_digest),
        "payload": payload,
        "schemaVersion": event.schema_version,
        "sensitivity": sensitivity,
        "sequence": event.sequence,
        "timestampUnixMicros": event.timestamp,
    });
    serde_json::to_vec(&value)
        .map(|encoded| encoded.len())
        .map_err(|_| ReplayError::Integrity("encode canonical replay event".to_owned()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(*byte >> 4)]));
        output.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    output
}

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

    /// Checks one live event immediately before it becomes eligible for delivery.
    fn inspect_event(
        &self,
        session: &ReplaySession,
        event: &ReplayEvent,
    ) -> Result<(), ReplayError> {
        self.inspect(session, std::slice::from_ref(event))
    }

    /// Checks an acknowledgement immediately before durable cursor mutation.
    fn inspect_ack(&self, _session: &ReplaySession) -> Result<(), ReplayError> {
        Ok(())
    }
}

/// Inputs used to acquire a current replay authorization lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayAuthorizationRequest {
    pub principal_id: String,
    pub authority_id: [u8; 16],
    pub session_generation: i64,
    pub expected_epoch: i64,
    pub session_id: Option<[u8; 16]>,
    pub scope: Option<ReplayScope>,
}

/// Current authorization values that may fence exactly one replay operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayAuthorizationLease {
    principal_id: String,
    authorization_epoch: i64,
    sensitivity_ceiling: Sensitivity,
}

impl ReplayAuthorizationLease {
    pub fn new(
        principal_id: impl Into<String>,
        authorization_epoch: i64,
        sensitivity_ceiling: Sensitivity,
    ) -> Result<Self, ReplayError> {
        let principal_id = principal_id.into();
        if principal_id.is_empty() || authorization_epoch < 0 {
            return Err(ReplayError::AuthorizationRevoked);
        }
        Ok(Self {
            principal_id,
            authorization_epoch,
            sensitivity_ceiling,
        })
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub const fn authorization_epoch(&self) -> i64 {
        self.authorization_epoch
    }

    pub const fn sensitivity_ceiling(&self) -> Sensitivity {
        self.sensitivity_ceiling
    }
}

/// Current authorization authority for replay open/page/ack/live operations.
pub trait ReplayAuthorizationPort: Send + Sync {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError>;
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
        floor_cursor: Option<Box<ReplayCursor>>,
        gap_range_ref: GapRangeRef,
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

impl AuthorizedDeliveryGuard {
    fn revalidate(&self) -> Result<(), ReplayError> {
        let current = self.authorization.current_lease(&self.request)?;
        if current != self.lease {
            return Err(ReplayError::AuthorizationRevoked);
        }
        Ok(())
    }

    fn inspect_sensitivity(&self, event: &ReplayEvent) -> Result<(), ReplayError> {
        let event_sensitivity = match event.sensitivity {
            0 => Sensitivity::Public,
            1 => Sensitivity::Internal,
            2 => Sensitivity::Sensitive,
            _ => {
                return Err(ReplayError::Integrity(
                    "invalid delivered replay sensitivity".to_owned(),
                ));
            }
        };
        let rank = |value| match value {
            Sensitivity::Public => 0,
            Sensitivity::Internal => 1,
            Sensitivity::Sensitive => 2,
        };
        if rank(event_sensitivity) > rank(self.lease.sensitivity_ceiling()) {
            return Err(ReplayError::SensitivityDenied);
        }
        Ok(())
    }
}

impl ReplayDeliveryPrecommitGuard for AuthorizedDeliveryGuard {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError> {
        for event in events {
            self.inspect_sensitivity(event)?;
        }
        self.delegate.inspect(session, events)?;
        self.revalidate()
    }

    fn inspect_event(
        &self,
        session: &ReplaySession,
        event: &ReplayEvent,
    ) -> Result<(), ReplayError> {
        self.revalidate()?;
        self.inspect_sensitivity(event)?;
        self.delegate.inspect_event(session, event)?;
        self.revalidate()
    }

    fn inspect_ack(&self, session: &ReplaySession) -> Result<(), ReplayError> {
        self.delegate.inspect_ack(session)?;
        self.revalidate()
    }
}

impl ReplayService {
    pub fn new(
        store: Arc<dyn ReplayStorePort>,
        server_secret: [u8; 32],
        lineage_id: EventLogLineageId,
        authorization: Arc<dyn ReplayAuthorizationPort>,
    ) -> Self {
        Self {
            store,
            authorization,
            server_secret,
            lineage_id,
        }
    }

    fn authorization_request(
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        expected_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
    ) -> Result<ReplayAuthorizationRequest, ReplayError> {
        Ok(ReplayAuthorizationRequest {
            principal_id: principal_id.to_owned(),
            authority_id: *authority_id,
            session_generation,
            expected_epoch,
            session_id: None,
            scope: Some(ReplayScope::Aggregate {
                aggregate_type: u8::try_from(aggregate_type).map_err(|_| {
                    ReplayError::Integrity("invalid replay authorization scope".to_owned())
                })?,
                aggregate_id: *aggregate_id,
            }),
        })
    }

    fn session_authorization_request(
        session_id: &[u8; 16],
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        expected_epoch: i64,
    ) -> ReplayAuthorizationRequest {
        ReplayAuthorizationRequest {
            principal_id: principal_id.to_owned(),
            authority_id: *authority_id,
            session_generation,
            expected_epoch,
            session_id: Some(*session_id),
            scope: None,
        }
    }

    fn acquire_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        let lease = self.authorization.current_lease(request)?;
        if lease.principal_id() != request.principal_id
            || lease.authorization_epoch() != request.expected_epoch
        {
            return Err(ReplayError::AuthorizationRevoked);
        }
        Ok(lease)
    }

    fn authorized_guard(
        &self,
        request: ReplayAuthorizationRequest,
        lease: ReplayAuthorizationLease,
        delegate: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Arc<dyn ReplayDeliveryPrecommitGuard> {
        Arc::new(AuthorizedDeliveryGuard {
            authorization: Arc::clone(&self.authorization),
            request,
            lease,
            delegate,
        })
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
        let request = Self::authorization_request(
            principal_id,
            session_generation,
            authority_id,
            authorization_epoch,
            aggregate_type,
            aggregate_id,
        )?;
        let lease = self.acquire_lease(&request)?;
        let result = self
            .store
            .open_session(
                principal_id,
                session_generation,
                authority_id,
                lease.authorization_epoch(),
                aggregate_type,
                aggregate_id,
                from_cursor.as_ref(),
                &self.lineage_id,
                &self.server_secret,
                self.authorized_guard(request.clone(), lease.clone(), delivery_guard),
            )
            .await?;
        match result {
            ReplayOpenResult::Opened { session, events } => Ok((session, events)),
            ReplayOpenResult::RetentionGap {
                floor_event,
                gap_range_ref,
            } => {
                let current_lease = self.acquire_lease(&request)?;
                if current_lease != lease {
                    return Err(ReplayError::AuthorizationRevoked);
                }
                let sensitivity_ceiling = current_lease.sensitivity_ceiling();
                let floor_cursor = floor_event
                    .filter(|event| {
                        let rank = |value| match value {
                            Sensitivity::Public => 0,
                            Sensitivity::Internal => 1,
                            Sensitivity::Sensitive => 2,
                        };
                        rank(match event.sensitivity {
                            0 => Sensitivity::Public,
                            1 => Sensitivity::Internal,
                            2 => Sensitivity::Sensitive,
                            _ => return false,
                        }) <= rank(sensitivity_ceiling)
                    })
                    .map(|event| {
                        self.build_cursor(
                            &event,
                            &ReplayScope::Aggregate {
                                aggregate_type: u8::try_from(aggregate_type).unwrap_or_default(),
                                aggregate_id: *aggregate_id,
                            },
                        )
                    })
                    .transpose()?;
                Err(ReplayError::ReplayRetentionGap {
                    floor_cursor: floor_cursor.map(Box::new),
                    gap_range_ref,
                })
            }
        }
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
        let request = Self::session_authorization_request(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
        );
        let lease = self.acquire_lease(&request)?;
        self.store
            .read_page(
                session_id,
                principal_id,
                generation,
                authority_id,
                lease.authorization_epoch(),
                limit,
                self.authorized_guard(request, lease, delivery_guard),
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
        let request = Self::authorization_request(
            principal_id,
            generation,
            authority_id,
            epoch,
            match &cursor.scope {
                ReplayScope::Aggregate { aggregate_type, .. } => i32::from(*aggregate_type),
                _ => {
                    return Err(ReplayError::CursorInvalid {
                        reason: "unsupported acknowledgement scope".to_owned(),
                    });
                }
            },
            match &cursor.scope {
                ReplayScope::Aggregate { aggregate_id, .. } => aggregate_id,
                _ => unreachable!("scope was checked above"),
            },
        )?;
        let lease = self.acquire_lease(&request)?;
        self.store
            .acknowledge(
                session_id,
                principal_id,
                generation,
                authority_id,
                lease.authorization_epoch(),
                cursor,
                self.authorized_guard(request, lease, Arc::new(NoopDeliveryGuard)),
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
        let request = Self::session_authorization_request(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
        );
        let lease = self.acquire_lease(&request)?;
        self.store
            .poll_live(
                session_id,
                principal_id,
                generation,
                authority_id,
                lease.authorization_epoch(),
                self.authorized_guard(request, lease, delivery_guard),
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

struct NoopDeliveryGuard;

impl ReplayDeliveryPrecommitGuard for NoopDeliveryGuard {
    fn inspect(
        &self,
        _session: &ReplaySession,
        _events: &[ReplayEvent],
    ) -> Result<(), ReplayError> {
        Ok(())
    }
}
