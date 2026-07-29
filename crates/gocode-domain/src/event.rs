//! Three-stage domain event model: draft → uncommitted → envelope.
//!
//! ```text
//! Domain decide  → DomainEventDraft<E>
//! Application     → UncommittedEvent<E>  (+ EventId, CommandContext, causation_id)
//! Persistence     → EventEnvelope<E>     (+ sequence, timestamp, integrity_digest)
//! ```

use core::fmt;

use crate::id::{
    AggregateId, CommandId, EventId, IdempotencyKey, IntegrityDigest, InvalidIdReason,
    MAX_ACTOR_BYTES, MAX_EVENT_TYPE_BYTES,
};
use crate::timestamp::Timestamp;

// ── Sensitivity ────────────────────────────────────────────────────────────

/// Data sensitivity classification for an event.
///
/// Determined deterministically from the event type — not a runtime choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    /// May be logged, relayed, and stored without special handling.
    Public,
    /// Restricted to the runtime process; not for external distribution.
    Internal,
    /// Contains secrets or PII; must be redacted in logs and diagnostics.
    Sensitive,
}

// ── AggregateType ──────────────────────────────────────────────────────────

/// Discriminant for aggregate kind, used in error messages and routing.
///
/// Note: forward-declared in `id.rs`; this is the canonical definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AggregateType {
    /// Task run aggregate.
    TaskRun,
    /// Conversation aggregate.
    Conversation,
    /// Workspace aggregate.
    Workspace,
}

impl fmt::Display for AggregateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TaskRun => write!(f, "TaskRun"),
            Self::Conversation => write!(f, "Conversation"),
            Self::Workspace => write!(f, "Workspace"),
        }
    }
}

// ── Actor ──────────────────────────────────────────────────────────────────

/// Identity of the actor that issued a command.
///
/// Bounded by `MAX_ACTOR_BYTES` (256), ASCII printable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Actor(String);

impl Actor {
    /// Create a new `Actor`, validating bounds.
    pub fn new(s: impl Into<String>) -> Result<Self, InvalidIdReason> {
        let s = s.into();
        if s.is_empty() {
            return Err(InvalidIdReason::Empty);
        }
        let len = s.len();
        if len > MAX_ACTOR_BYTES {
            return Err(InvalidIdReason::TooLong {
                max: MAX_ACTOR_BYTES,
                actual: len,
            });
        }
        Ok(Self(s))
    }

    /// Return a reference to the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── EventType ──────────────────────────────────────────────────────────────

/// Canonical event type name, bounded by `MAX_EVENT_TYPE_BYTES` (128).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventType(String);

impl EventType {
    /// Create a new `EventType`, validating bounds.
    pub fn new(s: impl Into<String>) -> Result<Self, InvalidIdReason> {
        let s = s.into();
        if s.is_empty() {
            return Err(InvalidIdReason::Empty);
        }
        let len = s.len();
        if len > MAX_EVENT_TYPE_BYTES {
            return Err(InvalidIdReason::TooLong {
                max: MAX_EVENT_TYPE_BYTES,
                actual: len,
            });
        }
        Ok(Self(s))
    }

    /// Return a reference to the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── CommandContext ─────────────────────────────────────────────────────────

/// Context carried by every command: identity, correlation, idempotency.
#[derive(Debug, Clone)]
pub struct CommandContext {
    /// Unique identifier for this command.
    pub command_id: CommandId,
    /// Client-provided idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Identity of the actor issuing the command.
    pub actor: Actor,
}

// ── DomainEventDraft ───────────────────────────────────────────────────────

/// Domain-layer output from `decide()` — aggregates produce these.
///
/// The application layer materializes drafts into [`UncommittedEvent`]s
/// by assigning an [`EventId`], [`CommandContext`], and building a
/// `causation_id` chain.
#[derive(Debug, Clone)]
pub struct DomainEventDraft<E> {
    /// Aggregate that produced this event.
    pub(crate) aggregate_id: AggregateId,
    /// Aggregate that correlates this event with its causal stream.
    pub(crate) correlation_id: AggregateId,
    /// Schema version for forward compatibility.
    pub(crate) schema_version: u32,
    /// Sensitivity classification (deterministic from event type).
    pub(crate) sensitivity: Sensitivity,
    /// Domain event payload.
    pub(crate) payload: E,
}

impl<E> DomainEventDraft<E> {
    /// Create a new draft.
    pub fn new(
        aggregate_id: AggregateId,
        correlation_id: AggregateId,
        schema_version: u32,
        sensitivity: Sensitivity,
        payload: E,
    ) -> Self {
        Self {
            aggregate_id,
            correlation_id,
            schema_version,
            sensitivity,
            payload,
        }
    }

    /// Return a reference to the aggregate ID.
    pub fn aggregate_id(&self) -> &AggregateId {
        &self.aggregate_id
    }

    /// Return a reference to the correlation aggregate ID.
    pub fn correlation_id(&self) -> &AggregateId {
        &self.correlation_id
    }

    /// Return the schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Return a reference to the sensitivity classification.
    pub fn sensitivity(&self) -> &Sensitivity {
        &self.sensitivity
    }

    /// Return a reference to the payload.
    pub fn payload(&self) -> &E {
        &self.payload
    }

    /// Consume the draft and return the payload.
    pub fn into_payload(self) -> E {
        self.payload
    }
}

// ── UncommittedEvent ───────────────────────────────────────────────────────

/// Application-layer event — materialized from a [`DomainEventDraft`]
/// with assigned identity, command context, and causation chain.
#[derive(Debug, Clone)]
pub struct UncommittedEvent<E> {
    pub(crate) event_id: EventId,
    pub(crate) aggregate_id: AggregateId,
    pub(crate) correlation_id: AggregateId,
    pub(crate) causation_id: Option<EventId>,
    pub(crate) command_id: CommandId,
    pub(crate) idempotency_key: IdempotencyKey,
    pub(crate) schema_version: u32,
    pub(crate) actor: Actor,
    pub(crate) sensitivity: Sensitivity,
    pub(crate) payload: E,
}

impl<E> UncommittedEvent<E> {
    /// Return a reference to the event ID.
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// Return a reference to the aggregate ID.
    pub fn aggregate_id(&self) -> &AggregateId {
        &self.aggregate_id
    }

    /// Return a reference to the correlation aggregate ID.
    pub fn correlation_id(&self) -> &AggregateId {
        &self.correlation_id
    }

    /// Return the causation event ID, if any.
    pub fn causation_id(&self) -> Option<&EventId> {
        self.causation_id.as_ref()
    }

    /// Return a reference to the command ID.
    pub fn command_id(&self) -> &CommandId {
        &self.command_id
    }

    /// Return a reference to the idempotency key.
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Return the schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Return a reference to the actor.
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Return a reference to the sensitivity.
    pub fn sensitivity(&self) -> &Sensitivity {
        &self.sensitivity
    }

    /// Return a reference to the payload.
    pub fn payload(&self) -> &E {
        &self.payload
    }

    /// Construct an [`UncommittedEvent`] from all its parts.
    ///
    /// Used by persistence adapters for integrity digest computation.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        event_id: EventId,
        aggregate_id: AggregateId,
        correlation_id: AggregateId,
        causation_id: Option<EventId>,
        command_id: CommandId,
        idempotency_key: IdempotencyKey,
        schema_version: u32,
        actor: Actor,
        sensitivity: Sensitivity,
        payload: E,
    ) -> Self {
        Self {
            event_id,
            aggregate_id,
            correlation_id,
            causation_id,
            command_id,
            idempotency_key,
            schema_version,
            actor,
            sensitivity,
            payload,
        }
    }

    /// Assemble an [`EventEnvelope`] from persisted parts.
    ///
    /// This method ONLY constructs a representation — it does **not** prove
    /// that a transaction was committed or that `integrity_digest` matches
    /// canonical payload bytes. Durable commit proof belongs to the
    /// persistence adapter, not this type.
    pub fn into_envelope(
        self,
        sequence: u64,
        timestamp: Timestamp,
        integrity_digest: IntegrityDigest,
    ) -> EventEnvelope<E> {
        EventEnvelope {
            event_id: self.event_id,
            aggregate_id: self.aggregate_id,
            correlation_id: self.correlation_id,
            causation_id: self.causation_id,
            command_id: self.command_id,
            idempotency_key: self.idempotency_key,
            schema_version: self.schema_version,
            actor: self.actor,
            sensitivity: self.sensitivity,
            payload: self.payload,
            sequence,
            timestamp,
            integrity_digest,
        }
    }
}

// ── EventEnvelope ──────────────────────────────────────────────────────────

/// Persisted event — domain fields + persistence-owned metadata.
#[derive(Debug, Clone)]
pub struct EventEnvelope<E> {
    // domain-owned (from UncommittedEvent):
    pub(crate) event_id: EventId,
    pub(crate) aggregate_id: AggregateId,
    pub(crate) correlation_id: AggregateId,
    pub(crate) causation_id: Option<EventId>,
    pub(crate) command_id: CommandId,
    pub(crate) idempotency_key: IdempotencyKey,
    pub(crate) schema_version: u32,
    pub(crate) actor: Actor,
    pub(crate) sensitivity: Sensitivity,
    pub(crate) payload: E,
    // persistence-owned:
    pub(crate) sequence: u64,
    pub(crate) timestamp: Timestamp,
    pub(crate) integrity_digest: IntegrityDigest,
}

impl<E> EventEnvelope<E> {
    /// Return a reference to the event ID.
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// Return a reference to the aggregate ID.
    pub fn aggregate_id(&self) -> &AggregateId {
        &self.aggregate_id
    }

    /// Return a reference to the correlation aggregate ID.
    pub fn correlation_id(&self) -> &AggregateId {
        &self.correlation_id
    }

    /// Return the causation event ID, if any.
    pub fn causation_id(&self) -> Option<&EventId> {
        self.causation_id.as_ref()
    }

    /// Return a reference to the command ID.
    pub fn command_id(&self) -> &CommandId {
        &self.command_id
    }

    /// Return a reference to the idempotency key.
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Return the schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Return a reference to the actor.
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Return a reference to the sensitivity.
    pub fn sensitivity(&self) -> &Sensitivity {
        &self.sensitivity
    }

    /// Return a reference to the payload.
    pub fn payload(&self) -> &E {
        &self.payload
    }

    /// Return the sequence number (persistence-owned).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Return the timestamp (persistence-owned).
    pub fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Return the integrity digest (persistence-owned).
    pub fn integrity_digest(&self) -> &IntegrityDigest {
        &self.integrity_digest
    }

    /// Construct an [`EventEnvelope`] from all its parts.
    ///
    /// Used by persistence adapters when reconstructing events from
    /// database rows. All fields are provided explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        event_id: EventId,
        aggregate_id: AggregateId,
        correlation_id: AggregateId,
        causation_id: Option<EventId>,
        command_id: CommandId,
        idempotency_key: IdempotencyKey,
        schema_version: u32,
        actor: Actor,
        sensitivity: Sensitivity,
        payload: E,
        sequence: u64,
        timestamp: Timestamp,
        integrity_digest: IntegrityDigest,
    ) -> Self {
        Self {
            event_id,
            aggregate_id,
            correlation_id,
            causation_id,
            command_id,
            idempotency_key,
            schema_version,
            actor,
            sensitivity,
            payload,
            sequence,
            timestamp,
            integrity_digest,
        }
    }
}

// ── materialize_batch ──────────────────────────────────────────────────────

/// Application-owned batch materializer.
///
/// Creates a causal chain of [`UncommittedEvent`]s from a list of drafts.
///
/// - `event_ids`: ordered, unique EventIds (one per draft).
/// - `last_committed_event`: the most recent committed event's ID,
///   used as `causation_id` for the first draft.
/// - Each subsequent draft chains to the previous draft's event_id.
///
/// Rejects: mismatched lengths, duplicate EventIds.
pub fn materialize_batch<E>(
    drafts: Vec<DomainEventDraft<E>>,
    event_ids: &[EventId],
    last_committed_event: Option<EventId>,
    context: &CommandContext,
) -> Result<Vec<UncommittedEvent<E>>, BatchMaterializeError> {
    if drafts.len() != event_ids.len() {
        return Err(BatchMaterializeError::LengthMismatch {
            drafts: drafts.len(),
            event_ids: event_ids.len(),
        });
    }

    // Check for duplicate event IDs
    for i in 0..event_ids.len() {
        for j in (i + 1)..event_ids.len() {
            if event_ids[i] == event_ids[j] {
                return Err(BatchMaterializeError::DuplicateEventId {
                    event_id: event_ids[i],
                });
            }
        }
    }

    let mut result = Vec::with_capacity(drafts.len());
    let mut prev_event_id = last_committed_event;

    for (i, draft) in drafts.into_iter().enumerate() {
        let uncommitted = UncommittedEvent {
            event_id: event_ids[i],
            aggregate_id: draft.aggregate_id,
            correlation_id: draft.correlation_id,
            causation_id: prev_event_id,
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            schema_version: draft.schema_version,
            actor: context.actor.clone(),
            sensitivity: draft.sensitivity,
            payload: draft.payload,
        };
        prev_event_id = Some(event_ids[i]);
        result.push(uncommitted);
    }

    Ok(result)
}

// ── BatchMaterializeError ──────────────────────────────────────────────────

/// Error returned by [`materialize_batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchMaterializeError {
    /// The number of drafts does not match the number of event IDs.
    LengthMismatch {
        /// Number of drafts.
        drafts: usize,
        /// Number of event IDs.
        event_ids: usize,
    },
    /// A duplicate `EventId` was found in the ordered list.
    DuplicateEventId {
        /// The duplicated event ID.
        event_id: EventId,
    },
}

impl fmt::Display for BatchMaterializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthMismatch { drafts, event_ids } => {
                write!(
                    f,
                    "batch length mismatch: {} drafts, {} event IDs",
                    drafts, event_ids
                )
            }
            Self::DuplicateEventId { event_id } => {
                write!(f, "duplicate event ID in batch: {}", event_id)
            }
        }
    }
}

impl std::error::Error for BatchMaterializeError {}

// ── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";
    #[allow(dead_code)]
    const ID2: &str = "018f2e3a-7000-7000-8000-000000000001";
    #[allow(dead_code)]
    const ID3: &str = "018f2e3a-7000-7000-8000-000000000002";

    fn make_ids(count: u8) -> Vec<EventId> {
        let base: [u8; 16] = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        (0..count)
            .map(|i| {
                let mut bytes = base;
                bytes[15] = i;
                EventId::from_bytes(bytes)
            })
            .collect()
    }

    fn make_context() -> CommandContext {
        CommandContext {
            command_id: VALID_UUID.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("key-1").unwrap(),
            actor: Actor::new("test-actor").unwrap(),
        }
    }

    fn make_draft<E: Clone>(payload: E) -> DomainEventDraft<E> {
        let taskrun_id = VALID_UUID.parse().unwrap();
        let aggregate_id = AggregateId::TaskRun(taskrun_id);
        DomainEventDraft::new(
            aggregate_id.clone(),
            aggregate_id,
            1,
            Sensitivity::Public,
            payload,
        )
    }

    #[test]
    fn test_materialize_batch_single() {
        let drafts = vec![make_draft("event-1")];
        let ids = make_ids(1);
        let ctx = make_context();
        let result = materialize_batch(drafts, &ids, None, &ctx).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].event_id(), &ids[0]);
        assert_eq!(result[0].causation_id(), None);
        assert_eq!(result[0].payload(), &"event-1");
    }

    #[test]
    fn test_materialize_batch_chain() {
        let drafts = vec![make_draft(1u32), make_draft(2u32), make_draft(3u32)];
        let ids = make_ids(4);
        let ctx = make_context();
        let last_committed = Some(ids[0]); // use first id as last committed
        let result = materialize_batch(drafts, &ids[1..], last_committed, &ctx).unwrap();
        assert_eq!(result.len(), 3);
        // First: causation is last_committed
        assert_eq!(result[0].causation_id(), Some(&ids[0]));
        // Second: causation is previous event_id
        assert_eq!(result[1].causation_id(), Some(&ids[1]));
        // Third: causation is previous event_id
        assert_eq!(result[2].causation_id(), Some(&ids[2]));
    }

    #[test]
    fn test_materialize_batch_length_mismatch() {
        let drafts = vec![make_draft(1u32)];
        let ids = make_ids(2);
        let ctx = make_context();
        let err = materialize_batch(drafts, &ids, None, &ctx).unwrap_err();
        assert_eq!(
            err,
            BatchMaterializeError::LengthMismatch {
                drafts: 1,
                event_ids: 2
            }
        );
    }

    #[test]
    fn test_materialize_batch_duplicate_ids() {
        let drafts = vec![make_draft(1u32), make_draft(2u32)];
        let mut ids = make_ids(2);
        ids[1] = ids[0]; // duplicate
        let ctx = make_context();
        let err = materialize_batch(drafts, &ids, None, &ctx).unwrap_err();
        assert!(matches!(
            err,
            BatchMaterializeError::DuplicateEventId { .. }
        ));
    }

    #[test]
    fn test_sensitivity_values() {
        assert_ne!(Sensitivity::Public, Sensitivity::Internal);
        assert_ne!(Sensitivity::Public, Sensitivity::Sensitive);
    }

    #[test]
    fn test_actor_bounds() {
        assert!(Actor::new("").is_err());
        let too_long = "x".repeat(257);
        assert!(Actor::new(too_long).is_err());
        assert!(Actor::new("valid-actor").is_ok());
    }

    #[test]
    fn test_event_type_bounds() {
        assert!(EventType::new("").is_err());
        let too_long = "x".repeat(129);
        assert!(EventType::new(too_long).is_err());
        assert!(EventType::new("TaskRunCreated").is_ok());
    }

    #[test]
    fn test_into_envelope() {
        let draft = make_draft("envelope-test");
        let ids = make_ids(1);
        let ctx = make_context();
        let uncommitted = materialize_batch(vec![draft], &ids[..1], None, &ctx)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let ts = Timestamp::from_unix_micros(1000);
        let digest = IntegrityDigest::from_bytes([0; 32]);
        let envelope = uncommitted.into_envelope(1, ts, digest);
        assert_eq!(envelope.sequence(), 1);
        assert_eq!(*envelope.timestamp(), ts);
        assert_eq!(*envelope.integrity_digest(), digest);
        assert_eq!(*envelope.payload(), "envelope-test");
    }

    #[test]
    fn test_aggregate_type_display() {
        assert_eq!(AggregateType::TaskRun.to_string(), "TaskRun");
        assert_eq!(AggregateType::Conversation.to_string(), "Conversation");
        assert_eq!(AggregateType::Workspace.to_string(), "Workspace");
    }
}
