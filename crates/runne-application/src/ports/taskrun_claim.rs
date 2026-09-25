/// Stable identity for one installed execution node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionNodeId(pub String);

/// Runtime allocated monotonically increasing fencing token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskRunFence(pub u64);

/// Complete durable identity used to replay a committed claim before reading
/// its now-advanced TaskRun stream.
#[derive(Debug, Clone)]
pub struct TaskRunClaimLookup {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
}

/// Result of a read-only lookup. A miss must still be rechecked atomically by
/// `claim_task_run`, since another caller may commit after this lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunClaimLookupResult {
    Miss,
    Duplicate(TaskRunClaimReceipt),
}

/// Inputs needed for one atomic runtime-owned TaskRun claim.
#[derive(Debug, Clone)]
pub struct TaskRunClaimRequest {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_version: u64,
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub node_id: ExecutionNodeId,
    pub node_epoch: u64,
    /// Closed, versioned capability descriptor selected by the node registry.
    pub capability_descriptor: String,
    /// Requested lease duration. Store determines its authoritative expiry.
    pub lease_duration_ms: u64,
    pub admitted_event: UncommittedEvent<TaskRunEvent>,
    pub started_event: UncommittedEvent<TaskRunEvent>,
}

/// Durable receipt returned after claim commit or exact duplicate replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunClaimReceipt {
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub node_id: ExecutionNodeId,
    pub node_epoch: u64,
    pub fence: TaskRunFence,
    pub lease_expires_at: Timestamp,
    pub new_version: u64,
    pub admitted_event_id: EventId,
    pub started_event_id: EventId,
}

/// Result distinguishes a fresh claim from an exact idempotent replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunClaimResult {
    Committed(TaskRunClaimReceipt),
    Duplicate(TaskRunClaimReceipt),
}

/// Atomic boundary for assignment, fencing allocation, lease creation and events.
/// Implementations must perform every mutation in one transaction.
pub trait TaskRunClaimPort {
    /// Looks up the complete identity without allocating a fence, lease, or
    /// events. Conflicting reuse of a command ID or scope/key fails closed.
    fn lookup_task_run_claim(
        &self,
        lookup: TaskRunClaimLookup,
    ) -> Result<TaskRunClaimLookupResult, TaskRunClaimError>;

    /// Exact identity replays its stored receipt before checking current stream
    /// state; identity conflicts fail closed. A miss must atomically verify
    /// expected version, Queued state, the ordered canonical admission/start
    /// facts, and live node epoch/capacity/capability before allocating fence,
    /// assignment, and lease, appending both events, and storing the receipt.
    /// Any failure rolls back every mutation.
    fn claim_task_run(
        &self,
        request: TaskRunClaimRequest,
    ) -> Result<TaskRunClaimResult, TaskRunClaimError>;
}

/// Closed claim failure categories; errors never grant executor authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunClaimError {
    NotQueued,
    StaleVersion { expected: u64, actual: u64 },
    NodeUnavailable,
    CapabilityMismatch,
    IdempotencyConflict,
    CorruptData,
    Unavailable,
}
