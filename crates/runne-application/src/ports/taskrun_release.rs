/// Recovery authorization for an attempt proven never to have prepared dispatch.
#[derive(Debug, Clone)]
pub struct TaskRunNoEffectReleaseRequest {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_version: u64,
    pub identity: TaskRunAssignmentIdentity,
    pub failure_event: UncommittedEvent<TaskRunEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunNoEffectReleaseReceipt {
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub fence: TaskRunFence,
    pub failure_event_id: EventId,
    pub new_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunNoEffectReleaseResult {
    Released(TaskRunNoEffectReleaseReceipt),
    Duplicate(TaskRunNoEffectReleaseReceipt),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunNoEffectReleaseError {
    StaleAssignment,
    StaleVersion { expected: u64, actual: u64 },
    NotRunning,
    DispatchMayHaveStarted,
    IdempotencyConflict,
    CorruptData,
    Unavailable,
}

/// Recovery-only authority for atomically appending failure and freeing capacity.
pub trait TaskRunNoEffectReleasePort {
    fn release_taskrun_no_effect(
        &self,
        request: TaskRunNoEffectReleaseRequest,
    ) -> Result<TaskRunNoEffectReleaseResult, TaskRunNoEffectReleaseError>;
}
