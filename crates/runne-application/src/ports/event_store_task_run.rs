// ── TaskRun EventStore ──────────────────────────────────────────────────────

/// Reads committed event streams for an aggregate.
pub trait EventStore {
    /// Load the full committed event stream for a task run.
    ///
    /// Returns a [`LoadedStream`] or an [`EventStoreError`].
    fn load_task_run(&self, taskrun_id: TaskRunId) -> Result<LoadedStream, EventStoreError>;

    /// Lists committed TaskRun identities for authoritative lifecycle queries.
    ///
    /// Adapters that cannot provide the bounded identity list remain closed;
    /// callers must not infer that an unavailable list is empty.
    fn list_task_runs(&self) -> Result<Vec<TaskRunId>, EventStoreError> {
        Err(EventStoreError::Unavailable)
    }
}

/// The result of loading a task run's event stream.
#[derive(Debug, Clone)]
pub struct LoadedStream {
    /// All committed events, ordered by sequence number.
    pub events: Vec<EventEnvelope<TaskRunEvent>>,
    /// The current version of the stream (equals the last event's sequence,
    /// or 0 for an empty stream).
    pub current_version: u64,
    /// The ID of the last event in the stream, or `None` if empty.
    pub last_event_id: Option<EventId>,
}

/// Errors that can occur when reading from the event store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventStoreError {
    /// The aggregate was not found in the store.
    NotFound,
    /// The stored data is corrupt or unreadable.
    CorruptData,
    /// The store is temporarily unavailable.
    Unavailable,
}
