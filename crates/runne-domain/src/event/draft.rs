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
