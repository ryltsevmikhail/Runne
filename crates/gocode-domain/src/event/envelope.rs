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
