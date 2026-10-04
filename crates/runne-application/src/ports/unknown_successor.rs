/// Atomic repository boundary for an explicitly acknowledged successor to an
/// unresolved TaskRun effect.
pub trait UnknownSuccessorRepository: Send + Sync {
    /// Commits the predecessor fence, conversation marker, successor submit,
    /// occupation disposition, and immutable successor receipt together.
    fn supersede_unknown_task_run(
        &self,
        payload: UnknownSuccessorCommit,
    ) -> Result<UnknownSuccessorCommitResult, CommitError>;
}

/// Command input for the dedicated successor transaction. The store derives
/// the original typed input, selected route, and aggregate events itself.
#[derive(Debug, Clone)]
pub struct UnknownSuccessorCommit {
    /// Unique command identity.
    pub command_id: CommandId,
    /// Client idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Principal/runtime/operation scope.
    pub idempotency_scope: IdempotencyScope,
    /// Semantic fingerprint of predecessor, version, and acknowledgement.
    pub command_fingerprint: CommandFingerprint,
    /// Exact unresolved predecessor.
    pub predecessor_taskrun_id: TaskRunId,
    /// Predecessor stream version reviewed by the caller.
    pub expected_predecessor_version: u64,
    /// Fresh TaskRun identity allocated for this explicit successor.
    pub successor_taskrun_id: TaskRunId,
    /// Digest of the closed acknowledgement code and version.
    pub acknowledgement_digest: IntegrityDigest,
    /// Event IDs reserved for predecessor (optional), conversation marker,
    /// and the two successor submit events, in that order.
    pub event_ids: [EventId; 4],
    /// Domain actor recorded on every event.
    pub actor: runne_domain::event::Actor,
}

/// Durable versions returned by the atomic successor transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownSuccessorCommitResult {
    /// Exact predecessor stream.
    pub predecessor_taskrun_id: TaskRunId,
    /// Version after the optional unknown-supersession event.
    pub predecessor_version: u64,
    /// Conversation whose active generation was superseded.
    pub conversation_id: ConversationId,
    /// Version after the supersession marker.
    pub conversation_version: u64,
    /// Newly created successor TaskRun.
    pub successor_taskrun_id: TaskRunId,
    /// Version after Created + Submitted + Queued.
    pub successor_version: u64,
}
