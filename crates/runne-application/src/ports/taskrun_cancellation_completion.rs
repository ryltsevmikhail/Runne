/// Input for a runtime-owned terminalization of a never-claimed cancellation.
#[derive(Debug, Clone, Copy)]
pub struct CompleteQueuedCancellationInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
}

/// Input for completing a cancellation after claim but before text begin.
#[derive(Debug, Clone, Copy)]
pub struct CompleteClaimedTaskRunCancellationInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
}

/// Atomic request to complete a queued cancellation after proving no claim/effect.
#[derive(Debug, Clone)]
pub struct CompleteQueuedCancellationRequest {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_version: u64,
    pub cancellation_completed: UncommittedEvent<TaskRunEvent>,
}

/// Durable result for completing a queued cancellation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteQueuedCancellationReceipt {
    pub taskrun_id: TaskRunId,
    pub new_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompleteQueuedCancellationResult {
    Committed(CompleteQueuedCancellationReceipt),
    Duplicate(CompleteQueuedCancellationReceipt),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompleteQueuedCancellationError {
    StaleVersion { expected: u64, actual: u64 },
    NotCancelling,
    AlreadyClaimed,
    IdempotencyConflict,
    CorruptData,
    Unavailable,
}

/// Atomically terminalizes only a cancellation proven never to have been claimed.
pub trait TaskRunCancellationCompletionPort {
    fn complete_queued_cancellation(
        &self,
        request: CompleteQueuedCancellationRequest,
    ) -> Result<CompleteQueuedCancellationResult, CompleteQueuedCancellationError>;

    /// Atomically completes a cancellation that won after claim but before
    /// the text-generation begin boundary, after validating the exact durable
    /// claim and proving that no begin or provider effect was recorded.
    fn complete_claimed_taskrun_cancellation(
        &self,
        _request: CompleteQueuedCancellationRequest,
    ) -> Result<CompleteQueuedCancellationResult, CompleteQueuedCancellationError> {
        Err(CompleteQueuedCancellationError::Unavailable)
    }
}
