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
