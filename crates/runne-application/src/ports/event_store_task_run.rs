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

/// Maximum number of authoritative stream identities examined by one scan page.
pub const MAX_TASK_RUN_QUEUE_SCAN: usize = 256;

/// Bounded keyset scan request. Construct through `new` to enforce the bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskRunQueueScanRequest {
    after: Option<TaskRunId>,
    limit: usize,
}

impl TaskRunQueueScanRequest {
    pub fn new(after: Option<TaskRunId>, limit: usize) -> Option<Self> {
        (1..=MAX_TASK_RUN_QUEUE_SCAN)
            .contains(&limit)
            .then_some(Self { after, limit })
    }
    pub const fn after(self) -> Option<TaskRunId> { self.after }
    pub const fn limit(self) -> usize { self.limit }
}

/// Exact identity and version observed during the authoritative scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskRunQueueCandidate {
    pub taskrun_id: TaskRunId,
    pub current_version: u64,
}

/// Candidate scan page. `next_cursor` advances over every examined ID;
/// `reached_end` distinguishes exhaustion from a full page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunQueueScanPage {
    pub candidates: Vec<TaskRunQueueCandidate>,
    pub next_cursor: Option<TaskRunId>,
    pub reached_end: bool,
    pub examined: usize,
}

/// Read-only bounded queue scan port. Its result does not grant claim authority.
pub trait TaskRunQueueScanner {
    fn scan_queued_task_runs(
        &self,
        request: TaskRunQueueScanRequest,
    ) -> Result<TaskRunQueueScanPage, EventStoreError>;
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
