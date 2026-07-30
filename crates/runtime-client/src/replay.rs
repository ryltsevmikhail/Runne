//! Strict Aggregate replay protocol, validated delivery identity and recovery.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::{AuthenticatedRuntimeClient, CanonicalId};
use crate::sse::{RawSseFrame, SSE_SILENCE_TIMEOUT, SseDecodeError, SseDecoder};

const MAXIMUM_REPLAY_REQUEST_BYTES: usize = 8 * 1024;
const MAXIMUM_REPLAY_RESPONSE_BYTES: usize = 1024 * 1024;
const MAXIMUM_ERROR_RESPONSE_BYTES: usize = 8 * 1024;
const MAXIMUM_CURSOR_BYTES: usize = 8 * 1024;
const MAXIMUM_EVENT_TYPE_BYTES: usize = 128;
const MAXIMUM_TEXT_BYTES: usize = 64 * 1024;
const MAXIMUM_REASON_BYTES: usize = 4 * 1024;
const REPLAY_PAGE_LIMIT: usize = 256;
const MAXIMUM_TRACKED_IDENTITIES: usize = 512;
const CURSOR_PREFIX: &str = "gocode-replay-cursor-v1.";
const LIVE_RESET_INTERVAL: Duration = Duration::from_secs(30);

const RECONNECT_DELAYS: [Duration; 10] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(5),
    Duration::from_secs(5),
    Duration::from_secs(5),
    Duration::from_secs(5),
    Duration::from_secs(5),
];

/// Opaque ackable replay cursor.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ReplayCursor(String);

impl ReplayCursor {
    /// Rehydrates one opaque cursor from trusted native storage.
    ///
    /// # Errors
    ///
    /// Returns `CursorInvalid` when persisted bytes are not the exact bounded
    /// cursor wire value accepted by this client.
    pub fn from_storage_bytes(bytes: &[u8]) -> Result<Self, ReplayClientError> {
        wire::cursor_from_storage(bytes)
    }

    /// Returns the exact opaque bytes for native persistence.
    ///
    /// The bytes remain transport-opaque and this type intentionally provides
    /// no `serde`, `Debug` or `Display` implementation.
    #[must_use]
    pub const fn storage_bytes(&self) -> &[u8] {
        wire::cursor_storage_bytes(self)
    }
}

/// Opaque replay session identity.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ReplaySessionId([u8; 16]);

/// Opaque live-delivery identity.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct LiveDeliveryId(CanonicalId);

mod wire {
    use super::{LiveDeliveryId, ReplayClientError, ReplayClientErrorKind, ReplayCursor};

    pub(super) fn cursor(value: String) -> Result<ReplayCursor, ReplayClientError> {
        super::validate_cursor(&value)?;
        Ok(ReplayCursor(value))
    }

    pub(super) fn cursor_value(cursor: &ReplayCursor) -> &str {
        &cursor.0
    }

    pub(super) fn cursor_from_storage(bytes: &[u8]) -> Result<ReplayCursor, ReplayClientError> {
        let value = std::str::from_utf8(bytes)
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::CursorInvalid))?;
        cursor(value.to_owned())
    }

    pub(super) const fn cursor_storage_bytes(cursor: &ReplayCursor) -> &[u8] {
        cursor.0.as_bytes()
    }

    pub(super) fn session_id(value: &str) -> Result<super::ReplaySessionId, ReplayClientError> {
        let bytes = super::decode_lower_hex::<16>(value)
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse))?;
        if bytes == [0; 16] {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        Ok(super::ReplaySessionId(bytes))
    }

    pub(super) fn session_value(value: &super::ReplaySessionId) -> String {
        hex::encode(value.0)
    }

    pub(super) fn live_id(value: &str) -> Result<LiveDeliveryId, ReplayClientError> {
        let id = super::parse_uuid_v7(value)
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse))?;
        Ok(LiveDeliveryId(id))
    }
}

/// Published Aggregate replay scope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReplayAggregateKind {
    Conversation,
    TaskRun,
}

impl ReplayAggregateKind {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::Conversation => "conversation",
            Self::TaskRun => "taskRun",
        }
    }

    fn parse(value: &str) -> Result<Self, ReplayClientError> {
        match value {
            "conversation" => Ok(Self::Conversation),
            "taskRun" => Ok(Self::TaskRun),
            _ => Err(ReplayClientError::new(
                ReplayClientErrorKind::SchemaMismatch,
            )),
        }
    }
}

/// One exact Aggregate replay selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReplayScope {
    aggregate_kind: ReplayAggregateKind,
    aggregate_id: CanonicalId,
}

impl ReplayScope {
    #[must_use]
    pub const fn new(aggregate_kind: ReplayAggregateKind, aggregate_id: CanonicalId) -> Self {
        Self {
            aggregate_kind,
            aggregate_id,
        }
    }

    #[must_use]
    pub const fn aggregate_kind(self) -> ReplayAggregateKind {
        self.aggregate_kind
    }

    #[must_use]
    pub const fn aggregate_id(self) -> CanonicalId {
        self.aggregate_id
    }
}

/// Closed replay sensitivity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaySensitivity {
    Public,
    Internal,
    Sensitive,
}

/// Validated Conversation payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConversationReplayPayload {
    Created {
        workspace_id: CanonicalId,
    },
    MessageAppended {
        role: crate::ConversationMessageRole,
        message_id: CanonicalId,
        task_run_id: CanonicalId,
        attempt_id: CanonicalId,
        text: String,
    },
    GenerationFailed {
        task_run_id: CanonicalId,
        attempt_id: CanonicalId,
        reason: String,
    },
    Closed,
}

/// Validated closed `TaskRun` payload.
///
/// `TaskRun` projection is outside the Desktop slice, so the semantic value is
/// retained as validated public JSON while its event type remains explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRunReplayPayload {
    event_type: String,
    value: serde_json::Value,
}

impl TaskRunReplayPayload {
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    #[must_use]
    pub const fn value(&self) -> &serde_json::Value {
        &self.value
    }
}

/// Closed validated canonical replay payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalReplayPayload {
    Conversation(ConversationReplayPayload),
    TaskRun(TaskRunReplayPayload),
}

/// One validated canonical event without its transport cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalReplayEvent {
    event_id: CanonicalId,
    aggregate_kind: ReplayAggregateKind,
    aggregate_id: CanonicalId,
    sequence: u64,
    timestamp_unix_micros: i64,
    sensitivity: ReplaySensitivity,
    event_type: String,
    causation_event_id: Option<CanonicalId>,
    correlation_id: CanonicalId,
    correlation_kind: ReplayAggregateKind,
    payload: CanonicalReplayPayload,
    integrity_digest: [u8; 32],
    canonical_digest: [u8; 32],
}

impl CanonicalReplayEvent {
    #[must_use]
    pub const fn event_id(&self) -> CanonicalId {
        self.event_id
    }

    #[must_use]
    pub const fn aggregate_kind(&self) -> ReplayAggregateKind {
        self.aggregate_kind
    }

    #[must_use]
    pub const fn aggregate_id(&self) -> CanonicalId {
        self.aggregate_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn timestamp_unix_micros(&self) -> i64 {
        self.timestamp_unix_micros
    }

    #[must_use]
    pub const fn sensitivity(&self) -> ReplaySensitivity {
        self.sensitivity
    }

    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    #[must_use]
    pub const fn causation_event_id(&self) -> Option<CanonicalId> {
        self.causation_event_id
    }

    #[must_use]
    pub const fn correlation_id(&self) -> CanonicalId {
        self.correlation_id
    }

    #[must_use]
    pub const fn correlation_kind(&self) -> ReplayAggregateKind {
        self.correlation_kind
    }

    #[must_use]
    pub const fn payload(&self) -> &CanonicalReplayPayload {
        &self.payload
    }

    #[must_use]
    pub const fn integrity_digest(&self) -> &[u8; 32] {
        &self.integrity_digest
    }

    #[must_use]
    pub const fn canonical_digest(&self) -> &[u8; 32] {
        &self.canonical_digest
    }
}

/// Whether a validated identity is new or an exact inclusive redelivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDeliveryDisposition {
    New,
    Duplicate,
}

/// Delivery exposed only after strict binding, schema and identity validation.
#[derive(Clone, Eq, PartialEq)]
pub struct ReplayDelivery {
    event: CanonicalReplayEvent,
    cursor: ReplayCursor,
    disposition: ReplayDeliveryDisposition,
    session_id: ReplaySessionId,
}

impl fmt::Debug for ReplayDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayDelivery")
            .field("event", &self.event)
            .field("cursor", &"[opaque]")
            .field("disposition", &self.disposition)
            .field("session_id", &"[opaque]")
            .finish()
    }
}

impl ReplayDelivery {
    #[must_use]
    pub const fn event(&self) -> &CanonicalReplayEvent {
        &self.event
    }

    #[must_use]
    pub const fn event_id(&self) -> CanonicalId {
        self.event.event_id()
    }

    #[must_use]
    pub const fn cursor(&self) -> &ReplayCursor {
        &self.cursor
    }

    #[must_use]
    pub const fn canonical_digest(&self) -> &[u8; 32] {
        self.event.canonical_digest()
    }

    #[must_use]
    pub const fn disposition(&self) -> ReplayDeliveryDisposition {
        self.disposition
    }
}

/// Closed recovery state consumed by `AppCore`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayRecoveryDisposition {
    Reconnectable,
    Incompatible,
    ResyncRequired,
    Revoked,
    Fatal,
}

/// Stable replay-client failure condition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayClientErrorKind {
    InvalidRequest,
    Transport,
    StreamSilence,
    Backpressure,
    SessionExpired,
    PeerIdentityMismatch,
    BindingMismatch,
    SchemaMismatch,
    RetentionGap,
    SensitivityDenied,
    AuthorizationRevoked,
    CursorInvalid,
    AggregateMismatch,
    NonMonotonicSequence,
    EventIdentityConflict,
    Integrity,
    LocalCallback,
    ResponseTooLarge,
    UnexpectedContentType,
    InvalidResponse,
}

impl ReplayClientErrorKind {
    #[must_use]
    pub const fn recovery_disposition(self) -> ReplayRecoveryDisposition {
        match self {
            Self::Transport | Self::StreamSilence | Self::Backpressure | Self::SessionExpired => {
                ReplayRecoveryDisposition::Reconnectable
            }
            Self::PeerIdentityMismatch
            | Self::BindingMismatch
            | Self::SchemaMismatch
            | Self::UnexpectedContentType
            | Self::InvalidResponse => ReplayRecoveryDisposition::Incompatible,
            Self::RetentionGap => ReplayRecoveryDisposition::ResyncRequired,
            Self::SensitivityDenied | Self::AuthorizationRevoked => {
                ReplayRecoveryDisposition::Revoked
            }
            Self::InvalidRequest
            | Self::CursorInvalid
            | Self::AggregateMismatch
            | Self::NonMonotonicSequence
            | Self::EventIdentityConflict
            | Self::Integrity
            | Self::LocalCallback
            | Self::ResponseTooLarge => ReplayRecoveryDisposition::Fatal,
        }
    }
}

/// Typed redacted replay-client failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayClientError {
    kind: ReplayClientErrorKind,
}

impl ReplayClientError {
    const fn new(kind: ReplayClientErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(&self) -> ReplayClientErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn recovery_disposition(&self) -> ReplayRecoveryDisposition {
        self.kind.recovery_disposition()
    }
}

impl fmt::Display for ReplayClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind.recovery_disposition() {
            ReplayRecoveryDisposition::Reconnectable => "runtime replay is temporarily unavailable",
            ReplayRecoveryDisposition::Incompatible => "runtime replay is incompatible",
            ReplayRecoveryDisposition::ResyncRequired => "runtime replay requires explicit resync",
            ReplayRecoveryDisposition::Revoked => "runtime replay authorization was revoked",
            ReplayRecoveryDisposition::Fatal => "runtime replay failed safely",
        })
    }
}

impl std::error::Error for ReplayClientError {}

/// Deterministic reconnect decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectDecision {
    RetryAfter(Duration),
    Exhausted,
}

/// Injectable monotonic clock and sleeper for deterministic reconnect tests.
pub trait ReconnectRuntime: Sync {
    fn now(&self) -> Duration;

    fn sleep(&self, delay: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Bounded deterministic reconnect policy.
#[derive(Clone, Debug, Default)]
pub struct ReconnectPolicy {
    attempts: usize,
    live_since: Option<Duration>,
}

impl ReconnectPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempts: 0,
            live_since: None,
        }
    }

    #[must_use]
    pub fn record_failure(&mut self) -> ReconnectDecision {
        self.live_since = None;
        let Some(delay) = RECONNECT_DELAYS.get(self.attempts).copied() else {
            return ReconnectDecision::Exhausted;
        };
        self.attempts = self.attempts.saturating_add(1);
        ReconnectDecision::RetryAfter(delay)
    }

    pub fn record_live_delivery(&mut self, now: Duration) {
        let started = *self.live_since.get_or_insert(now);
        if now.saturating_sub(started) >= LIVE_RESET_INTERVAL {
            self.attempts = 0;
            self.live_since = Some(now);
        }
    }

    pub fn record_live_delivery_with(&mut self, runtime: &impl ReconnectRuntime) {
        self.record_live_delivery(runtime.now());
    }

    pub async fn wait_after_failure(
        &mut self,
        runtime: &impl ReconnectRuntime,
    ) -> ReconnectDecision {
        let decision = self.record_failure();
        if let ReconnectDecision::RetryAfter(delay) = decision {
            runtime.sleep(delay).await;
        }
        decision
    }
}

#[derive(Clone, Eq, PartialEq)]
struct SeenIdentity {
    cursor: ReplayCursor,
    canonical_digest: [u8; 32],
}

#[derive(Default)]
struct IdentityState {
    seen: HashMap<CanonicalId, SeenIdentity>,
    order: VecDeque<CanonicalId>,
    last_sequence: Option<u64>,
    scope: Option<ReplayScope>,
}

/// Shareable identity history for inclusive reconnect deduplication.
#[derive(Clone, Default)]
pub struct ReplayIdentityTracker {
    inner: Arc<Mutex<IdentityState>>,
}

impl ReplayIdentityTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

struct DeliveryValidator {
    scope: ReplayScope,
    binding_id: Option<[u8; 16]>,
    identities: ReplayIdentityTracker,
}

impl DeliveryValidator {
    const fn new(scope: ReplayScope, identities: ReplayIdentityTracker) -> Self {
        Self {
            scope,
            binding_id: None,
            identities,
        }
    }

    fn validate(
        &mut self,
        wire_event: CanonicalEventWire,
        cursor_value: String,
        session_id: ReplaySessionId,
    ) -> Result<ReplayDelivery, ReplayClientError> {
        let cursor = wire::cursor(cursor_value)?;
        let binding = decode_lower_hex::<16>(&wire_event.replay_binding_id)
            .filter(|value| *value != [0; 16])
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::BindingMismatch))?;
        match self.binding_id {
            Some(expected) if expected != binding => {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::BindingMismatch,
                ));
            }
            None => self.binding_id = Some(binding),
            _ => {}
        }

        let canonical = validate_canonical_event(wire_event)?;
        if canonical.aggregate_kind != self.scope.aggregate_kind
            || canonical.aggregate_id != self.scope.aggregate_id
        {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::AggregateMismatch,
            ));
        }

        let mut identities = self
            .identities
            .inner
            .lock()
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Integrity))?;
        match identities.scope {
            Some(expected) if expected != self.scope => {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::BindingMismatch,
                ));
            }
            None => identities.scope = Some(self.scope),
            _ => {}
        }
        let identity = SeenIdentity {
            cursor: cursor.clone(),
            canonical_digest: canonical.canonical_digest,
        };
        let disposition = if let Some(existing) = identities.seen.get(&canonical.event_id) {
            if existing != &identity {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::EventIdentityConflict,
                ));
            }
            ReplayDeliveryDisposition::Duplicate
        } else {
            if identities
                .last_sequence
                .is_some_and(|last| last.checked_add(1) != Some(canonical.sequence))
            {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::NonMonotonicSequence,
                ));
            }
            identities.last_sequence = Some(canonical.sequence);
            identities.seen.insert(canonical.event_id, identity);
            identities.order.push_back(canonical.event_id);
            if identities.order.len() > MAXIMUM_TRACKED_IDENTITIES {
                let oldest = identities
                    .order
                    .pop_front()
                    .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::Integrity))?;
                identities.seen.remove(&oldest);
            }
            ReplayDeliveryDisposition::New
        };
        drop(identities);

        Ok(ReplayDelivery {
            event: canonical,
            cursor,
            disposition,
            session_id,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenSessionRequestWire<'a> {
    aggregate_type: &'static str,
    aggregate_id: String,
    from_cursor: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpenSessionResponseWire {
    session_id: String,
    high_water_ref: String,
    events: Vec<serde_json::Value>,
    has_more: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadPageRequestWire {
    limit: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadPageResponseWire {
    events: Vec<serde_json::Value>,
    has_more: bool,
}

#[derive(Serialize)]
struct AcknowledgeRequestWire<'a> {
    cursor: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcknowledgeResponseWire {
    acknowledged: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompleteCatchUpResponseWire {
    catch_up_proof: String,
    session_state: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContinueLiveResponseWire {
    live_delivery_id: String,
    session_state: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalEventWire {
    event_id: String,
    aggregate_type: String,
    aggregate_id: String,
    sequence: u64,
    timestamp_unix_micros: i64,
    sensitivity: String,
    schema_version: u32,
    event_type: String,
    causation_event_id: Option<String>,
    integrity_digest: String,
    correlation_id: String,
    correlation_type: String,
    payload: serde_json::Value,
    replay_binding_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SseDeliveryWire {
    transport_version: u32,
    replay_session_id: String,
    live_delivery_id: Option<String>,
    delivery_sequence: u64,
    canonical_event: serde_json::Value,
    replay_cursor: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SseTerminalWire {
    transport_version: u32,
    code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorEnvelopeWire {
    code: String,
    request_id: String,
}

const EVENT_KEYS: &[&str] = &[
    "aggregateId",
    "aggregateType",
    "causationEventId",
    "correlationId",
    "correlationType",
    "eventId",
    "eventType",
    "integrityDigest",
    "payload",
    "replayBindingId",
    "schemaVersion",
    "sensitivity",
    "sequence",
    "timestampUnixMicros",
];

fn parse_http_delivery(
    mut value: serde_json::Value,
) -> Result<(CanonicalEventWire, String), ReplayClientError> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    validate_exact_keys_with_extra(object, EVENT_KEYS, "cursor")?;
    let cursor = object
        .remove("cursor")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::CursorInvalid))?;
    let event = serde_json::from_value(value)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    Ok((event, cursor))
}

fn parse_sse_event(value: serde_json::Value) -> Result<CanonicalEventWire, ReplayClientError> {
    let object = value
        .as_object()
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    validate_exact_keys(object, EVENT_KEYS)?;
    serde_json::from_value(value)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn validate_canonical_event(
    wire: CanonicalEventWire,
) -> Result<CanonicalReplayEvent, ReplayClientError> {
    if wire.schema_version != 1 {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    let aggregate_kind = ReplayAggregateKind::parse(&wire.aggregate_type)?;
    let aggregate_id = parse_uuid_v7(&wire.aggregate_id)?;
    let event_id = parse_uuid_v7(&wire.event_id)?;
    let causation_event_id = wire
        .causation_event_id
        .as_deref()
        .map(parse_uuid_v7)
        .transpose()?;
    let correlation_id = parse_uuid_v7(&wire.correlation_id)?;
    let correlation_kind = ReplayAggregateKind::parse(&wire.correlation_type)?;
    if wire.sequence == 0 {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::NonMonotonicSequence,
        ));
    }
    if wire.event_type.is_empty()
        || wire.event_type.len() > MAXIMUM_EVENT_TYPE_BYTES
        || wire.event_type.chars().any(char::is_control)
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    let sensitivity = match wire.sensitivity.as_str() {
        "public" => ReplaySensitivity::Public,
        "internal" => ReplaySensitivity::Internal,
        "sensitive" => ReplaySensitivity::Sensitive,
        _ => {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::SchemaMismatch,
            ));
        }
    };
    let integrity_digest = decode_lower_hex::<32>(&wire.integrity_digest)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::Integrity))?;
    if decode_lower_hex::<16>(&wire.replay_binding_id)
        .as_ref()
        .is_none_or(|value| *value == [0; 16])
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::BindingMismatch,
        ));
    }
    let payload_type = wire
        .payload
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    if payload_type != wire.event_type {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    let payload = validate_payload(aggregate_kind, &wire.event_type, wire.payload.clone())?;
    let mut canonical_value = serde_json::to_value(&wire)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Integrity))?;
    canonical_value
        .as_object_mut()
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::Integrity))?
        .remove("replayBindingId");
    let canonical_bytes = serde_json::to_vec(&canonical_value)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Integrity))?;
    let canonical_digest = Sha256::digest(canonical_bytes).into();

    Ok(CanonicalReplayEvent {
        event_id,
        aggregate_kind,
        aggregate_id,
        sequence: wire.sequence,
        timestamp_unix_micros: wire.timestamp_unix_micros,
        sensitivity,
        event_type: wire.event_type,
        causation_event_id,
        correlation_id,
        correlation_kind,
        payload,
        integrity_digest,
        canonical_digest,
    })
}

fn validate_payload(
    aggregate_kind: ReplayAggregateKind,
    event_type: &str,
    value: serde_json::Value,
) -> Result<CanonicalReplayPayload, ReplayClientError> {
    match aggregate_kind {
        ReplayAggregateKind::Conversation => validate_conversation_payload(event_type, &value)
            .map(CanonicalReplayPayload::Conversation),
        ReplayAggregateKind::TaskRun => {
            validate_task_run_payload(event_type, &value)?;
            Ok(CanonicalReplayPayload::TaskRun(TaskRunReplayPayload {
                event_type: event_type.to_owned(),
                value,
            }))
        }
    }
}

fn validate_conversation_payload(
    event_type: &str,
    value: &serde_json::Value,
) -> Result<ConversationReplayPayload, ReplayClientError> {
    let object = payload_object(value)?;
    match event_type {
        "conversation.created" => {
            validate_exact_keys(object, &["type", "workspaceId"])?;
            Ok(ConversationReplayPayload::Created {
                workspace_id: uuid_field(object, "workspaceId")?,
            })
        }
        "conversation.message.appended" => {
            validate_exact_keys(
                object,
                &[
                    "attemptId",
                    "messageId",
                    "role",
                    "taskRunId",
                    "text",
                    "type",
                ],
            )?;
            let role = match string_field(object, "role")? {
                "user" => crate::ConversationMessageRole::User,
                "assistant" => crate::ConversationMessageRole::Assistant,
                _ => {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::SchemaMismatch,
                    ));
                }
            };
            let text = bounded_string_field(object, "text", MAXIMUM_TEXT_BYTES)?;
            Ok(ConversationReplayPayload::MessageAppended {
                role,
                message_id: uuid_field(object, "messageId")?,
                task_run_id: uuid_field(object, "taskRunId")?,
                attempt_id: uuid_field(object, "attemptId")?,
                text: text.to_owned(),
            })
        }
        "conversation.generation.failed" => {
            validate_exact_keys(object, &["attemptId", "reason", "taskRunId", "type"])?;
            Ok(ConversationReplayPayload::GenerationFailed {
                task_run_id: uuid_field(object, "taskRunId")?,
                attempt_id: uuid_field(object, "attemptId")?,
                reason: bounded_string_field(object, "reason", MAXIMUM_REASON_BYTES)?.to_owned(),
            })
        }
        "conversation.closed" => {
            validate_exact_keys(object, &["type"])?;
            Ok(ConversationReplayPayload::Closed)
        }
        _ => Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        )),
    }
}

#[allow(clippy::too_many_lines)]
fn validate_task_run_payload(
    event_type: &str,
    value: &serde_json::Value,
) -> Result<(), ReplayClientError> {
    let object = payload_object(value)?;
    match event_type {
        "taskRun.created"
        | "taskRun.queued"
        | "taskRun.admitted"
        | "taskRun.wait.started"
        | "taskRun.resumed"
        | "taskRun.checkpoint.started"
        | "taskRun.checkpoint.committed"
        | "taskRun.cancellation.requested"
        | "taskRun.cancellation.completed"
        | "taskRun.budget.exhausted"
        | "taskRun.policy.denied"
        | "taskRun.reconciliation.started"
        | "taskRun.reconciliation.completed"
        | "taskRun.unrecoverable"
        | "taskRun.cancelled" => validate_exact_keys(object, &["type"]),
        "taskRun.attempt.started" | "taskRun.retry.started" | "taskRun.retry.completed" => {
            validate_exact_keys(object, &["attemptId", "type"])?;
            uuid_field(object, "attemptId").map(|_| ())
        }
        "taskRun.completed" => {
            validate_exact_keys(object, &["outcome", "reason", "type"])?;
            match string_field(object, "outcome")? {
                "success" if object.get("reason").is_some_and(serde_json::Value::is_null) => Ok(()),
                "failure" => {
                    bounded_string_field(object, "reason", MAXIMUM_REASON_BYTES).map(|_| ())
                }
                _ => Err(ReplayClientError::new(
                    ReplayClientErrorKind::SchemaMismatch,
                )),
            }
        }
        "taskRun.failed" => {
            validate_exact_keys(object, &["reason", "type"])?;
            bounded_string_field(object, "reason", MAXIMUM_REASON_BYTES).map(|_| ())
        }
        "taskRun.loop.cycle.started" => {
            validate_exact_keys(
                object,
                &["attemptId", "cycleId", "parentCycleId", "sequence", "type"],
            )?;
            uuid_field(object, "attemptId")?;
            uuid_field(object, "cycleId")?;
            optional_uuid_field(object, "parentCycleId")?;
            positive_u64_field(object, "sequence").map(|_| ())
        }
        "taskRun.context.committed" => {
            validate_exact_keys(object, &["cycleId", "manifestId", "revision", "type"])?;
            uuid_field(object, "cycleId")?;
            uuid_field(object, "manifestId")?;
            positive_u64_field(object, "revision").map(|_| ())
        }
        "taskRun.plan.committed" => {
            validate_exact_keys(
                object,
                &[
                    "cycleId",
                    "expectedProposalIndexes",
                    "planId",
                    "revision",
                    "type",
                ],
            )?;
            uuid_field(object, "cycleId")?;
            uuid_field(object, "planId")?;
            positive_u64_field(object, "revision")?;
            unique_u32_array_field(object, "expectedProposalIndexes")
        }
        "taskRun.step.outcome.recorded" => {
            validate_exact_keys(
                object,
                &["cycleId", "outcome", "proposalIndex", "stepId", "type"],
            )?;
            uuid_field(object, "cycleId")?;
            uuid_field(object, "stepId")?;
            u32_field(object, "proposalIndex")?;
            enum_field(
                object,
                "outcome",
                &[
                    "succeeded",
                    "failed_before_commit",
                    "failed_after_commit",
                    "uncertain",
                    "cancelled",
                ],
            )
        }
        "taskRun.loop.cycle.completed" => {
            validate_exact_keys(object, &["attemptId", "cycleId", "disposition", "type"])?;
            uuid_field(object, "attemptId")?;
            uuid_field(object, "cycleId")?;
            enum_field(
                object,
                "disposition",
                &["continue", "wait", "complete", "fail"],
            )
        }
        "taskRun.next.cycle.created" => {
            validate_exact_keys(
                object,
                &[
                    "attemptId",
                    "parentCycleId",
                    "sequence",
                    "successorCycleId",
                    "type",
                ],
            )?;
            uuid_field(object, "attemptId")?;
            uuid_field(object, "parentCycleId")?;
            uuid_field(object, "successorCycleId")?;
            positive_u64_field(object, "sequence").map(|_| ())
        }
        "taskRun.retry.scheduled" => {
            validate_exact_keys(
                object,
                &[
                    "abandonedCycleId",
                    "delayMillis",
                    "dueAtUnixMicros",
                    "newAttemptId",
                    "oldAttemptId",
                    "ordinal",
                    "type",
                ],
            )?;
            uuid_field(object, "abandonedCycleId")?;
            uuid_field(object, "newAttemptId")?;
            uuid_field(object, "oldAttemptId")?;
            u64_field(object, "delayMillis")?;
            i64_field(object, "dueAtUnixMicros")?;
            positive_u64_field(object, "ordinal").map(|_| ())
        }
        "taskRun.retry.attempt.activated" => {
            validate_exact_keys(
                object,
                &["activatedAtUnixMicros", "attemptId", "ordinal", "type"],
            )?;
            uuid_field(object, "attemptId")?;
            i64_field(object, "activatedAtUnixMicros")?;
            positive_u64_field(object, "ordinal").map(|_| ())
        }
        "taskRun.recovery.resume.started" => {
            validate_exact_keys(
                object,
                &["abandonedCycleId", "newAttemptId", "newGeneration", "type"],
            )?;
            optional_uuid_field(object, "abandonedCycleId")?;
            uuid_field(object, "newAttemptId")?;
            positive_u64_field(object, "newGeneration").map(|_| ())
        }
        "taskRun.loop.checkpoint.started"
        | "taskRun.loop.checkpoint.recorded"
        | "taskRun.loop.checkpoint.committed" => {
            validate_exact_keys(object, &["checkpointId", "type"])?;
            uuid_field(object, "checkpointId").map(|_| ())
        }
        "taskRun.loop.wake.accepted" => {
            validate_exact_keys(object, &["cycleId", "evidenceId", "source", "type"])?;
            uuid_field(object, "cycleId")?;
            uuid_field(object, "evidenceId")?;
            enum_field(
                object,
                "source",
                &[
                    "external_input",
                    "approval",
                    "child_task_run",
                    "timer",
                    "reconciliation",
                ],
            )
        }
        _ => Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        )),
    }
}

fn payload_object(
    value: &serde_json::Value,
) -> Result<&serde_json::Map<String, serde_json::Value>, ReplayClientError> {
    value
        .as_object()
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn validate_exact_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
) -> Result<(), ReplayClientError> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    Ok(())
}

fn validate_exact_keys_with_extra(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
    extra: &str,
) -> Result<(), ReplayClientError> {
    if object.len() != expected.len().saturating_add(1)
        || !object.contains_key(extra)
        || expected.iter().any(|key| !object.contains_key(*key))
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    Ok(())
}

fn string_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, ReplayClientError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn bounded_string_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    maximum_bytes: usize,
) -> Result<&'a str, ReplayClientError> {
    let value = string_field(object, key)?;
    if value.is_empty() || value.len() > maximum_bytes {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    Ok(value)
}

fn uuid_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<CanonicalId, ReplayClientError> {
    parse_uuid_v7(string_field(object, key)?)
}

fn optional_uuid_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<CanonicalId>, ReplayClientError> {
    match object.get(key) {
        Some(value) if value.is_null() => Ok(None),
        Some(value) => value
            .as_str()
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
            .and_then(parse_uuid_v7)
            .map(Some),
        None => Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        )),
    }
}

fn u64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, ReplayClientError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn positive_u64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, ReplayClientError> {
    let value = u64_field(object, key)?;
    if value == 0 {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    Ok(value)
}

fn u32_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u32, ReplayClientError> {
    u32::try_from(u64_field(object, key)?)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn i64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<i64, ReplayClientError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn enum_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    allowed: &[&str],
) -> Result<(), ReplayClientError> {
    if allowed.contains(&string_field(object, key)?) {
        Ok(())
    } else {
        Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ))
    }
}

fn unique_u32_array_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<(), ReplayClientError> {
    let values = object
        .get(key)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    let mut unique = HashSet::with_capacity(values.len());
    for value in values {
        let value = value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
        if !unique.insert(value) {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::SchemaMismatch,
            ));
        }
    }
    Ok(())
}

impl AuthenticatedRuntimeClient {
    /// Applies and acknowledges bounded catch-up pages, then enters live mode.
    ///
    /// The callback always runs before acknowledgement, including for exact
    /// duplicates. A callback failure is terminal and leaves the cursor
    /// unacknowledged.
    ///
    /// # Errors
    ///
    /// Returns a closed replay failure without advancing past the failing
    /// delivery.
    pub async fn catch_up<F, E>(
        &self,
        scope: ReplayScope,
        from_cursor: Option<&ReplayCursor>,
        apply: F,
    ) -> Result<ReplayLiveSession, ReplayClientError>
    where
        F: FnMut(&ReplayDelivery) -> Result<(), E>,
    {
        self.catch_up_with_identities(scope, from_cursor, ReplayIdentityTracker::new(), apply)
            .await
    }

    /// Catch-up using caller-retained identity history across reconnects.
    ///
    /// # Errors
    ///
    /// Returns a closed replay failure without acknowledging a delivery whose
    /// callback or validation failed.
    pub async fn catch_up_with_identities<F, E>(
        &self,
        scope: ReplayScope,
        from_cursor: Option<&ReplayCursor>,
        identities: ReplayIdentityTracker,
        mut apply: F,
    ) -> Result<ReplayLiveSession, ReplayClientError>
    where
        F: FnMut(&ReplayDelivery) -> Result<(), E>,
    {
        let request = OpenSessionRequestWire {
            aggregate_type: scope.aggregate_kind.wire_value(),
            aggregate_id: scope.aggregate_id.to_string(),
            from_cursor: from_cursor.map(wire::cursor_value),
        };
        let open: OpenSessionResponseWire = self
            .post_replay_json("/v1/replay/open-session", &request)
            .await?;
        let session_id = wire::session_id(&open.session_id)?;
        validate_bounded_lower_hex(&open.high_water_ref, MAXIMUM_CURSOR_BYTES)?;
        let mut validator = DeliveryValidator::new(scope, identities);
        let mut events = open.events;
        if events.len() > REPLAY_PAGE_LIMIT {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::ResponseTooLarge,
            ));
        }
        let mut has_more = open.has_more;

        loop {
            if has_more && events.is_empty() {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::InvalidResponse,
                ));
            }
            for value in events {
                let (wire_event, cursor) = parse_http_delivery(value)?;
                let delivery = validator.validate(wire_event, cursor, session_id.clone())?;
                apply(&delivery)
                    .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::LocalCallback))?;
                self.acknowledge_replay(&session_id, delivery.cursor())
                    .await?;
            }
            if !has_more {
                break;
            }
            let path = format!("/v1/replay/{}/read-page", wire::session_value(&session_id));
            let page: ReadPageResponseWire = self
                .post_replay_json(
                    &path,
                    &ReadPageRequestWire {
                        limit: REPLAY_PAGE_LIMIT,
                    },
                )
                .await?;
            if page.events.len() > REPLAY_PAGE_LIMIT {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::ResponseTooLarge,
                ));
            }
            events = page.events;
            has_more = page.has_more;
        }

        let session_path = wire::session_value(&session_id);
        let completed: CompleteCatchUpResponseWire = self
            .post_replay_empty(&format!("/v1/replay/{session_path}/complete-catch-up"))
            .await?;
        if completed.session_state != "catch_up_complete" {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        validate_bounded_lower_hex(&completed.catch_up_proof, MAXIMUM_CURSOR_BYTES)?;

        let live: ContinueLiveResponseWire = self
            .post_replay_empty(&format!("/v1/replay/{session_path}/continue-live"))
            .await?;
        if live.session_state != "live" {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        let live_delivery_id = wire::live_id(&live.live_delivery_id)?;

        Ok(ReplayLiveSession {
            client: self.clone(),
            scope,
            session_id,
            live_delivery_id,
            validator,
            response: None,
            decoder: SseDecoder::default(),
            pending: VecDeque::new(),
            last_delivery_sequence: None,
            terminal_returned: false,
            unacknowledged: None,
        })
    }

    async fn acknowledge_replay(
        &self,
        session_id: &ReplaySessionId,
        cursor: &ReplayCursor,
    ) -> Result<(), ReplayClientError> {
        let path = format!("/v1/replay/{}/acknowledge", wire::session_value(session_id));
        let response: AcknowledgeResponseWire = self
            .post_replay_json(
                &path,
                &AcknowledgeRequestWire {
                    cursor: wire::cursor_value(cursor),
                },
            )
            .await?;
        if !response.acknowledged {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        Ok(())
    }

    async fn post_replay_json<T, R>(&self, path: &str, body: &T) -> Result<R, ReplayClientError>
    where
        T: Serialize + Sync + ?Sized,
        R: serde::de::DeserializeOwned,
    {
        let body = serde_json::to_vec(body)
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::InvalidRequest))?;
        if body.len() > MAXIMUM_REPLAY_REQUEST_BYTES {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidRequest,
            ));
        }
        let request = self
            .authenticated_request(self.http_client().post(self.url(path)))
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        let response = request
            .send()
            .await
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
        read_replay_json(response).await
    }

    async fn post_replay_empty<R>(&self, path: &str) -> Result<R, ReplayClientError>
    where
        R: serde::de::DeserializeOwned,
    {
        let request = self
            .authenticated_request(self.http_client().post(self.url(path)))
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
        let response = request
            .send()
            .await
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
        read_replay_json(response).await
    }
}

/// Closed terminal SSE code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayTerminalCode {
    SessionExpired,
    AuthorizationRevoked,
    SensitivityDenied,
    RetentionGap,
    UnsupportedSchema,
    Backpressure,
    Integrity,
}

impl ReplayTerminalCode {
    fn parse(value: &str) -> Result<Self, ReplayClientError> {
        match value {
            "replay_session_expired" => Ok(Self::SessionExpired),
            "replay_authorization_revoked" => Ok(Self::AuthorizationRevoked),
            "replay_sensitivity_denied" => Ok(Self::SensitivityDenied),
            "replay_retention_gap" => Ok(Self::RetentionGap),
            "replay_unsupported_schema" => Ok(Self::UnsupportedSchema),
            "replay_backpressure" => Ok(Self::Backpressure),
            "runtime_invariant_violation" => Ok(Self::Integrity),
            _ => Err(ReplayClientError::new(
                ReplayClientErrorKind::SchemaMismatch,
            )),
        }
    }

    #[must_use]
    pub const fn recovery_disposition(self) -> ReplayRecoveryDisposition {
        match self {
            Self::SessionExpired | Self::Backpressure => ReplayRecoveryDisposition::Reconnectable,
            Self::UnsupportedSchema => ReplayRecoveryDisposition::Incompatible,
            Self::RetentionGap => ReplayRecoveryDisposition::ResyncRequired,
            Self::AuthorizationRevoked | Self::SensitivityDenied => {
                ReplayRecoveryDisposition::Revoked
            }
            Self::Integrity => ReplayRecoveryDisposition::Fatal,
        }
    }
}

/// Validated terminal replay notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayTerminal {
    code: ReplayTerminalCode,
}

impl ReplayTerminal {
    #[must_use]
    pub const fn code(self) -> ReplayTerminalCode {
        self.code
    }

    #[must_use]
    pub const fn recovery_disposition(self) -> ReplayRecoveryDisposition {
        self.code.recovery_disposition()
    }
}

/// One validated live stream item.
#[derive(Clone, Eq, PartialEq)]
pub enum ReplayStreamEvent {
    Delivery(Box<ReplayDelivery>),
    Terminal(ReplayTerminal),
    Heartbeat,
}

impl fmt::Debug for ReplayStreamEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delivery(delivery) => formatter.debug_tuple("Delivery").field(delivery).finish(),
            Self::Terminal(terminal) => formatter.debug_tuple("Terminal").field(terminal).finish(),
            Self::Heartbeat => formatter.write_str("Heartbeat"),
        }
    }
}

/// Live replay session after explicit catch-up completion proof.
pub struct ReplayLiveSession {
    client: AuthenticatedRuntimeClient,
    scope: ReplayScope,
    session_id: ReplaySessionId,
    live_delivery_id: LiveDeliveryId,
    validator: DeliveryValidator,
    response: Option<reqwest::Response>,
    decoder: SseDecoder,
    pending: VecDeque<RawSseFrame>,
    last_delivery_sequence: Option<u64>,
    terminal_returned: bool,
    unacknowledged: Option<ReplayCursor>,
}

impl ReplayLiveSession {
    #[must_use]
    pub const fn scope(&self) -> ReplayScope {
        self.scope
    }

    #[must_use]
    pub const fn session_id(&self) -> &ReplaySessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn live_delivery_id(&self) -> &LiveDeliveryId {
        &self.live_delivery_id
    }

    /// Receives the next validated delivery, heartbeat or terminal frame.
    ///
    /// EOF and silence are reconnectable transport failures and are never
    /// interpreted as replay completion.
    ///
    /// # Errors
    ///
    /// Returns a closed replay failure for transport silence/EOF or any
    /// malformed, oversized, mismatched or terminally invalid frame.
    pub async fn next_event(&mut self) -> Result<ReplayStreamEvent, ReplayClientError> {
        if self.unacknowledged.is_some() {
            return Err(ReplayClientError::new(ReplayClientErrorKind::LocalCallback));
        }
        if self.terminal_returned {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        self.ensure_stream().await?;
        let silence_deadline = tokio::time::Instant::now() + SSE_SILENCE_TIMEOUT;
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return self.decode_stream_frame(frame);
            }
            let response = self
                .response
                .as_mut()
                .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
            let next = tokio::time::timeout_at(silence_deadline, response.chunk())
                .await
                .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::StreamSilence))?
                .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
            let Some(chunk) = next else {
                self.decoder.finish().map_err(map_sse_decode_error)?;
                return Err(ReplayClientError::new(ReplayClientErrorKind::Transport));
            };
            let frames = self.decoder.push(&chunk).map_err(map_sse_decode_error)?;
            self.pending.extend(frames);
        }
    }

    /// Acknowledges one delivery after `AppCore` has committed it locally.
    ///
    /// # Errors
    ///
    /// Returns a binding or transport failure without changing local state.
    pub async fn acknowledge(
        &mut self,
        delivery: &ReplayDelivery,
    ) -> Result<(), ReplayClientError> {
        if delivery.session_id != self.session_id {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::BindingMismatch,
            ));
        }
        if self.unacknowledged.as_ref() != Some(delivery.cursor()) {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::EventIdentityConflict,
            ));
        }
        self.client
            .acknowledge_replay(&self.session_id, delivery.cursor())
            .await?;
        self.unacknowledged = None;
        Ok(())
    }

    async fn ensure_stream(&mut self) -> Result<(), ReplayClientError> {
        if self.response.is_some() {
            return Ok(());
        }
        let path = format!(
            "/v1/replay/{}/events",
            wire::session_value(&self.session_id)
        );
        let request = self
            .client
            .authenticated_request(self.client.http_client().get(self.client.url(&path)))
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?
            .header(ACCEPT, "text/event-stream");
        let response = request
            .send()
            .await
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
        if response.status().as_u16() != 200 {
            return Err(read_replay_error(response).await);
        }
        ensure_content_type(&response, "text/event-stream")?;
        self.response = Some(response);
        Ok(())
    }

    fn decode_stream_frame(
        &mut self,
        frame: RawSseFrame,
    ) -> Result<ReplayStreamEvent, ReplayClientError> {
        match frame {
            RawSseFrame::Heartbeat => Ok(ReplayStreamEvent::Heartbeat),
            RawSseFrame::Terminal(bytes) => {
                let terminal: SseTerminalWire = serde_json::from_slice(&bytes)
                    .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
                if terminal.transport_version != 1 {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::SchemaMismatch,
                    ));
                }
                let terminal = ReplayTerminal {
                    code: ReplayTerminalCode::parse(&terminal.code)?,
                };
                self.terminal_returned = true;
                Ok(ReplayStreamEvent::Terminal(terminal))
            }
            RawSseFrame::Delivery(bytes) => {
                let wire: SseDeliveryWire = serde_json::from_slice(&bytes)
                    .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
                if wire.transport_version != 1 {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::SchemaMismatch,
                    ));
                }
                if wire::session_id(&wire.replay_session_id)? != self.session_id
                    || wire
                        .live_delivery_id
                        .as_deref()
                        .map(wire::live_id)
                        .transpose()?
                        .as_ref()
                        != Some(&self.live_delivery_id)
                {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::BindingMismatch,
                    ));
                }
                let expected_delivery_sequence = self
                    .last_delivery_sequence
                    .map_or(Some(1), |last| last.checked_add(1));
                if Some(wire.delivery_sequence) != expected_delivery_sequence {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::NonMonotonicSequence,
                    ));
                }
                self.last_delivery_sequence = Some(wire.delivery_sequence);
                let event = parse_sse_event(wire.canonical_event)?;
                let delivery =
                    self.validator
                        .validate(event, wire.replay_cursor, self.session_id.clone())?;
                self.unacknowledged = Some(delivery.cursor().clone());
                Ok(ReplayStreamEvent::Delivery(Box::new(delivery)))
            }
        }
    }
}

async fn read_replay_json<T>(response: reqwest::Response) -> Result<T, ReplayClientError>
where
    T: serde::de::DeserializeOwned,
{
    if response.status().as_u16() != 200 {
        return Err(read_replay_error(response).await);
    }
    ensure_content_type(&response, "application/json")?;
    let body = read_bounded(response, MAXIMUM_REPLAY_RESPONSE_BYTES).await?;
    serde_json::from_slice(&body)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

async fn read_replay_error(response: reqwest::Response) -> ReplayClientError {
    let status = response.status().as_u16();
    if ensure_content_type(&response, "application/json").is_err() {
        return ReplayClientError::new(ReplayClientErrorKind::UnexpectedContentType);
    }
    let body = match read_bounded(response, MAXIMUM_ERROR_RESPONSE_BYTES).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    let envelope: ErrorEnvelopeWire = match serde_json::from_slice(&body) {
        Ok(envelope) => envelope,
        Err(_) => return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse),
    };
    if parse_uuid_v7(&envelope.request_id).is_err() {
        return ReplayClientError::new(ReplayClientErrorKind::InvalidResponse);
    }
    let kind = match (status, envelope.code.as_str()) {
        (
            400,
            "invalid_request"
            | "invalid_aggregate_id"
            | "unsupported_replay_scope"
            | "invalid_replay_page_limit"
            | "invalid_replay_session_id",
        )
        | (413, "request_too_large") => ReplayClientErrorKind::InvalidRequest,
        (401, "unauthorized" | "replay_authorization_revoked") => {
            ReplayClientErrorKind::AuthorizationRevoked
        }
        (403, "replay_sensitivity_denied") => ReplayClientErrorKind::SensitivityDenied,
        (404, "replay_session_not_found")
        | (409, "replay_session_conflict")
        | (410, "replay_session_expired") => ReplayClientErrorKind::SessionExpired,
        (409, "replay_unsupported_schema") => ReplayClientErrorKind::SchemaMismatch,
        (400, "invalid_replay_cursor") | (409, "replay_cursor_regression") => {
            ReplayClientErrorKind::CursorInvalid
        }
        (409, "replay_page_in_progress") | (429 | 503, "replay_backpressure") => {
            ReplayClientErrorKind::Backpressure
        }
        (410, "replay_retention_gap") => ReplayClientErrorKind::RetentionGap,
        (503, "runtime_unavailable") => ReplayClientErrorKind::Transport,
        (500, "runtime_invariant_violation") => ReplayClientErrorKind::Integrity,
        _ => ReplayClientErrorKind::InvalidResponse,
    };
    ReplayClientError::new(kind)
}

async fn read_bounded(
    mut response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ReplayClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(maximum_bytes).unwrap_or(u64::MAX))
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::ResponseTooLarge,
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?
    {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::ResponseTooLarge,
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn ensure_content_type(
    response: &reqwest::Response,
    expected: &str,
) -> Result<(), ReplayClientError> {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some(expected) {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::UnexpectedContentType,
        ));
    }
    Ok(())
}

const fn map_sse_decode_error(error: SseDecodeError) -> ReplayClientError {
    let kind = match error {
        SseDecodeError::FrameTooLarge => ReplayClientErrorKind::ResponseTooLarge,
        SseDecodeError::UnknownEvent => ReplayClientErrorKind::SchemaMismatch,
        SseDecodeError::InvalidUtf8
        | SseDecodeError::Nul
        | SseDecodeError::InvalidLineEnding
        | SseDecodeError::UnknownField
        | SseDecodeError::MissingEvent
        | SseDecodeError::MissingData
        | SseDecodeError::MultipleData
        | SseDecodeError::DataAfterTerminal
        | SseDecodeError::IncompleteFrame => ReplayClientErrorKind::Integrity,
    };
    ReplayClientError::new(kind)
}

fn parse_uuid_v7(value: &str) -> Result<CanonicalId, ReplayClientError> {
    let id = CanonicalId::parse(value)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    if id.to_string() != value {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    Ok(id)
}

fn decode_lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.saturating_mul(2)
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).ok()?;
    Some(bytes)
}

fn validate_bounded_lower_hex(value: &str, maximum_bytes: usize) -> Result<(), ReplayClientError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || !value.len().is_multiple_of(2)
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::InvalidResponse,
        ));
    }
    Ok(())
}

fn validate_cursor(value: &str) -> Result<(), ReplayClientError> {
    if value.len() > MAXIMUM_CURSOR_BYTES {
        return Err(ReplayClientError::new(ReplayClientErrorKind::CursorInvalid));
    }
    let encoded = value
        .strip_prefix(CURSOR_PREFIX)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::CursorInvalid))?;
    if encoded.is_empty()
        || !encoded.len().is_multiple_of(2)
        || encoded
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ReplayClientError::new(ReplayClientErrorKind::CursorInvalid));
    }
    let bytes = hex::decode(encoded)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::CursorInvalid))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::CursorInvalid))?;
    if !value.is_object() {
        return Err(ReplayClientError::new(ReplayClientErrorKind::CursorInvalid));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "aggregateId": "018f2e3a-7000-7000-8000-000000000110",
            "aggregateType": "conversation",
            "causationEventId": "018f2e3a-7000-7000-8000-000000000111",
            "correlationId": "018f2e3a-7000-7000-8000-000000000110",
            "correlationType": "conversation",
            "cursor": "gocode-replay-cursor-v1.7b7d",
            "eventId": "018f2e3a-7000-7000-8000-000000000112",
            "eventType": "conversation.message.appended",
            "integrityDigest": "1111111111111111111111111111111111111111111111111111111111111111",
            "payload": {
                "attemptId": "018f2e3a-7000-7000-8000-000000000114",
                "messageId": "018f2e3a-7000-7000-8000-000000000115",
                "role": "assistant",
                "taskRunId": "018f2e3a-7000-7000-8000-000000000113",
                "text": "bounded text",
                "type": "conversation.message.appended"
            },
            "replayBindingId": "018f2e3a700070008000000000000121",
            "schemaVersion": 1,
            "sensitivity": "sensitive",
            "sequence": 2,
            "timestampUnixMicros": 1_722_330_000_000_000_i64
        })
    }

    fn validator() -> DeliveryValidator {
        DeliveryValidator::new(
            ReplayScope::new(
                ReplayAggregateKind::Conversation,
                CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
            ),
            ReplayIdentityTracker::new(),
        )
    }

    fn session() -> ReplaySessionId {
        wire::session_id("018f2e3a700070008000000000000118").unwrap()
    }

    fn validate(
        validator: &mut DeliveryValidator,
        value: serde_json::Value,
    ) -> Result<ReplayDelivery, ReplayClientError> {
        let (event, cursor) = parse_http_delivery(value)?;
        validator.validate(event, cursor, session())
    }

    #[test]
    fn strict_delivery_rejects_extra_and_missing_fields() {
        let mut extra = fixture();
        extra
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::json!(true));
        assert_eq!(
            validate(&mut validator(), extra).unwrap_err().kind(),
            ReplayClientErrorKind::SchemaMismatch
        );

        let mut missing = fixture();
        missing.as_object_mut().unwrap().remove("eventType");
        assert_eq!(
            validate(&mut validator(), missing).unwrap_err().kind(),
            ReplayClientErrorKind::SchemaMismatch
        );
    }

    #[test]
    fn strict_delivery_rejects_malformed_identity_digest_cursor_and_schema() {
        let cases = [
            ("eventId", serde_json::json!("not-a-uuid")),
            ("integrityDigest", serde_json::json!("AA")),
            ("cursor", serde_json::json!("gocode-replay-cursor-v1.00")),
            ("schemaVersion", serde_json::json!(2)),
        ];
        for (field, replacement) in cases {
            let mut value = fixture();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), replacement);
            assert!(validate(&mut validator(), value).is_err(), "{field}");
        }
    }

    #[test]
    fn strict_delivery_rejects_unknown_payload_wrong_aggregate_and_binding() {
        let mut payload = fixture();
        payload["payload"]["unexpected"] = serde_json::json!(true);
        assert_eq!(
            validate(&mut validator(), payload).unwrap_err().kind(),
            ReplayClientErrorKind::SchemaMismatch
        );

        let mut aggregate = fixture();
        aggregate["aggregateId"] = serde_json::json!("018f2e3a-7000-7000-8000-000000000119");
        assert_eq!(
            validate(&mut validator(), aggregate).unwrap_err().kind(),
            ReplayClientErrorKind::AggregateMismatch
        );

        let mut validator = validator();
        validate(&mut validator, fixture()).unwrap();
        let mut binding = fixture();
        binding["eventId"] = serde_json::json!("018f2e3a-7000-7000-8000-000000000119");
        binding["sequence"] = serde_json::json!(3);
        binding["replayBindingId"] = serde_json::json!("018f2e3a700070008000000000000122");
        assert_eq!(
            validate(&mut validator, binding).unwrap_err().kind(),
            ReplayClientErrorKind::BindingMismatch
        );
    }

    #[test]
    fn dedup_is_exact_and_never_auto_advances_conflicting_identity() {
        let mut validator = validator();
        assert_eq!(
            validate(&mut validator, fixture()).unwrap().disposition(),
            ReplayDeliveryDisposition::New
        );
        assert_eq!(
            validate(&mut validator, fixture()).unwrap().disposition(),
            ReplayDeliveryDisposition::Duplicate
        );

        let mut conflicting_cursor = fixture();
        conflicting_cursor["cursor"] = serde_json::json!("gocode-replay-cursor-v1.7b2261223a317d");
        assert_eq!(
            validate(&mut validator, conflicting_cursor)
                .unwrap_err()
                .kind(),
            ReplayClientErrorKind::EventIdentityConflict
        );
    }

    #[test]
    fn new_event_sequence_must_increase_monotonically() {
        let mut validator = validator();
        validate(&mut validator, fixture()).unwrap();
        let mut next = fixture();
        next["eventId"] = serde_json::json!("018f2e3a-7000-7000-8000-000000000119");
        next["cursor"] = serde_json::json!("gocode-replay-cursor-v1.7b2261223a317d");
        assert_eq!(
            validate(&mut validator, next).unwrap_err().kind(),
            ReplayClientErrorKind::NonMonotonicSequence
        );

        let mut gap = fixture();
        gap["eventId"] = serde_json::json!("018f2e3a-7000-7000-8000-000000000119");
        gap["cursor"] = serde_json::json!("gocode-replay-cursor-v1.7b2261223a317d");
        gap["sequence"] = serde_json::json!(4);
        assert_eq!(
            validate(&mut validator, gap).unwrap_err().kind(),
            ReplayClientErrorKind::NonMonotonicSequence
        );
    }

    #[test]
    fn reconnect_binding_changes_do_not_change_stable_event_identity() {
        let identities = ReplayIdentityTracker::new();
        let scope = ReplayScope::new(
            ReplayAggregateKind::Conversation,
            CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
        );
        let mut first = DeliveryValidator::new(scope, identities.clone());
        validate(&mut first, fixture()).unwrap();

        let mut rebound = fixture();
        rebound["replayBindingId"] = serde_json::json!("018f2e3a700070008000000000000122");
        let mut second = DeliveryValidator::new(scope, identities);
        assert_eq!(
            validate(&mut second, rebound).unwrap().disposition(),
            ReplayDeliveryDisposition::Duplicate
        );
    }

    #[tokio::test]
    async fn catch_up_applies_before_each_ack_then_enters_live() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let expected = [
                "/v1/replay/open-session",
                "/v1/replay/018f2e3a700070008000000000000118/acknowledge",
                "/v1/replay/018f2e3a700070008000000000000118/read-page",
                "/v1/replay/018f2e3a700070008000000000000118/acknowledge",
                "/v1/replay/018f2e3a700070008000000000000118/complete-catch-up",
                "/v1/replay/018f2e3a700070008000000000000118/continue-live",
            ];
            for (index, expected_path) in expected.into_iter().enumerate() {
                let (path, body) = read_request(&mut stream).await;
                assert_eq!(path, expected_path);
                if index == 1 {
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["cursor"],
                        "gocode-replay-cursor-v1.7b7d"
                    );
                }
                if index == 3 {
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["cursor"],
                        "gocode-replay-cursor-v1.7b2261223a317d"
                    );
                }
                let response = match index {
                    0 => serde_json::json!({
                        "sessionId": "018f2e3a700070008000000000000118",
                        "highWaterRef": "aa",
                        "events": [fixture()],
                        "hasMore": true
                    }),
                    1 | 3 => serde_json::json!({"acknowledged": true}),
                    2 => {
                        let mut event = fixture();
                        event["eventId"] =
                            serde_json::json!("018f2e3a-7000-7000-8000-000000000119");
                        event["eventType"] = serde_json::json!("conversation.closed");
                        event["payload"] = serde_json::json!({"type": "conversation.closed"});
                        event["sequence"] = serde_json::json!(3);
                        event["cursor"] =
                            serde_json::json!("gocode-replay-cursor-v1.7b2261223a317d");
                        serde_json::json!({"events": [event], "hasMore": false})
                    }
                    4 => serde_json::json!({
                        "catchUpProof": "aa",
                        "sessionState": "catch_up_complete"
                    }),
                    5 => serde_json::json!({
                        "liveDeliveryId": "018f2e3a-7000-7000-8000-000000000117",
                        "sessionState": "live"
                    }),
                    _ => unreachable!(),
                };
                write_json(&mut stream, &response).await;
            }
        });

        let client = test_client(address);
        let scope = ReplayScope::new(
            ReplayAggregateKind::Conversation,
            CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
        );
        let mut applied = Vec::new();
        let live = client
            .catch_up(scope, None, |delivery| {
                applied.push(delivery.event_id());
                Ok::<_, ()>(())
            })
            .await
            .unwrap();

        assert_eq!(applied.len(), 2);
        assert_eq!(live.scope(), scope);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_rejects_unexpected_content_type_and_oversized_body_before_callback() {
        let cases = [
            (
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\n{}"
                    .to_owned(),
                ReplayClientErrorKind::UnexpectedContentType,
            ),
            (
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                    MAXIMUM_REPLAY_RESPONSE_BYTES + 1
                ),
                ReplayClientErrorKind::ResponseTooLarge,
            ),
        ];

        for (response, expected) in cases {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (path, _) = read_request(&mut stream).await;
                assert_eq!(path, "/v1/replay/open-session");
                stream.write_all(response.as_bytes()).await.unwrap();
            });
            let client = test_client(address);
            let scope = ReplayScope::new(
                ReplayAggregateKind::Conversation,
                CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
            );
            let mut callbacks = 0;
            let result = client
                .catch_up(scope, None, |_| {
                    callbacks += 1;
                    Ok::<_, ()>(())
                })
                .await;
            let Err(error) = result else {
                panic!("invalid response must fail before callback");
            };
            assert_eq!(error.kind(), expected);
            assert_eq!(callbacks, 0);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn live_delivery_requires_local_ack_before_reading_another_frame() {
        let mut live = test_live_session();
        let event = live_delivery_fixture(1);
        let decoded = live
            .decode_stream_frame(RawSseFrame::Delivery(serde_json::to_vec(&event).unwrap()))
            .unwrap();
        assert!(matches!(decoded, ReplayStreamEvent::Delivery(_)));

        assert_eq!(
            live.next_event().await.unwrap_err().kind(),
            ReplayClientErrorKind::LocalCallback
        );
    }

    #[test]
    fn live_delivery_sequence_must_start_at_one_and_remain_contiguous() {
        let mut live = test_live_session();
        assert_eq!(
            live.decode_stream_frame(RawSseFrame::Delivery(
                serde_json::to_vec(&live_delivery_fixture(2)).unwrap()
            ))
            .unwrap_err()
            .kind(),
            ReplayClientErrorKind::NonMonotonicSequence
        );
    }

    fn test_live_session() -> ReplayLiveSession {
        let scope = ReplayScope::new(
            ReplayAggregateKind::Conversation,
            CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
        );
        ReplayLiveSession {
            client: test_client("127.0.0.1:9".parse().unwrap()),
            scope,
            session_id: session(),
            live_delivery_id: wire::live_id("018f2e3a-7000-7000-8000-000000000117").unwrap(),
            validator: DeliveryValidator::new(scope, ReplayIdentityTracker::new()),
            response: None,
            decoder: SseDecoder::default(),
            pending: VecDeque::new(),
            last_delivery_sequence: None,
            terminal_returned: false,
            unacknowledged: None,
        }
    }

    fn live_delivery_fixture(delivery_sequence: u64) -> serde_json::Value {
        let mut canonical_event = fixture();
        canonical_event.as_object_mut().unwrap().remove("cursor");
        serde_json::json!({
            "transportVersion": 1,
            "replaySessionId": "018f2e3a700070008000000000000118",
            "liveDeliveryId": "018f2e3a-7000-7000-8000-000000000117",
            "deliverySequence": delivery_sequence,
            "canonicalEvent": canonical_event,
            "replayCursor": "gocode-replay-cursor-v1.7b7d"
        })
    }

    fn test_client(address: std::net::SocketAddr) -> AuthenticatedRuntimeClient {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        AuthenticatedRuntimeClient::from_local_session(
            client,
            format!("http://{address}"),
            crate::RuntimeSessionAuthority::from_local_session([7; 32]),
            crate::RuntimeSessionInfo {
                profile_id: crate::EXPECTED_BUNDLE_ID.to_owned(),
                schema_hash: crate::GOLDEN_BUNDLE_HASH.to_owned(),
                runtime_version: "test".to_owned(),
                capabilities: crate::REQUIRED_RUNTIME_CAPABILITIES
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                authority_id: "authority".to_owned(),
                principal_id: "local-owner".to_owned(),
                event_log_lineage_id: "lineage".to_owned(),
                daemon_instance_id: "instance".to_owned(),
                launch_generation: 1,
                session_id: "session".to_owned(),
                authorization_epoch: 0,
                sensitivity_ceiling: "sensitive".to_owned(),
                certificate_sha256: "certificate".to_owned(),
                capability_digest: "capabilities".to_owned(),
            },
        )
    }

    async fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0);
            request.extend_from_slice(&chunk[..read]);
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.strip_prefix("content-length: ")
                    .or_else(|| line.strip_prefix("Content-Length: "))
            })
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0);
            request.extend_from_slice(&chunk[..read]);
        }
        let path = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap()
            .to_owned();
        (
            path,
            request[header_end..header_end + content_length].to_vec(),
        )
    }

    async fn write_json(stream: &mut TcpStream, value: &serde_json::Value) {
        let body = serde_json::to_vec(value).unwrap();
        let headers = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
    }
}
