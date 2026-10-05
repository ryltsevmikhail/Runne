/// Exact provider terminal source included in D2 completion linkage evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D2ToolTerminalSourceV1 {
    pub dispatch_attempt_id: [u8; 16],
    pub sequence: u64,
    pub event_kind: u8,
    pub terminal: bool,
    pub plaintext_digest: IntegrityDigest,
    pub profile_digest: IntegrityDigest,
    pub runtime_generation: u64,
}

/// Atomic projection of a completed D2 TaskRun cycle into its original chat receipt.
#[derive(Debug, Clone)]
pub struct D2ToolLoopCompletionV1 {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_taskrun_head: u64,
    pub assignment: TaskRunAssignmentIdentity,
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub cycle_id: CycleId,
    pub evaluation_ref: PlanEvaluationRef,
    pub terminal_attempt_id: [u8; 16],
    pub terminal_outbox_id: [u8; 16],
    pub terminal_sequence: u64,
    pub settlement_digest: IntegrityDigest,
    pub terminal_sources: Vec<D2ToolTerminalSourceV1>,
    pub assistant_text_digest: IntegrityDigest,
    pub assistant_text_length: u64,
    pub conversation_id: ConversationId,
    pub conversation_event: UncommittedEvent<ConversationEvent>,
    pub started_receipt: TextGenerationReceipt,
    pub completed_receipt: TextGenerationReceipt,
}

/// Result of an idempotent D2 Conversation completion projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum D2ToolLoopCompletionResult {
    Committed { receipt: TextGenerationReceipt },
    Duplicate { receipt: TextGenerationReceipt },
}

/// Canonical same-writer transaction for D2 completion linkage and Conversation receipt.
pub trait D2ToolLoopCompletionPort {
    fn complete_d2_tool_loop(
        &self,
        completion: D2ToolLoopCompletionV1,
    ) -> Result<D2ToolLoopCompletionResult, CommitError>;
}

/// Atomic truthful projection after a canonical D2 loop failure.
#[derive(Debug, Clone)]
pub struct D2ToolLoopFailureV1 {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_taskrun_head: u64,
    pub assignment: TaskRunAssignmentIdentity,
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub cycle_id: CycleId,
    /// Current same-node launch epoch for recovery-only settlement.
    pub recovery_epoch: Option<u64>,
    pub reason: runne_domain::conversation::GenerationFailureReason,
    pub actor: runne_domain::event::Actor,
    pub conversation_id: ConversationId,
    pub conversation_event: UncommittedEvent<ConversationEvent>,
    pub started_receipt: TextGenerationReceipt,
    pub failed_receipt: TextGenerationReceipt,
}

/// Result of an idempotent D2 failure projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum D2ToolLoopFailureResult {
    Committed { receipt: TextGenerationReceipt },
    Duplicate { receipt: TextGenerationReceipt },
}

/// Same-writer projection for a failed D2 loop, without another TaskRun event.
pub trait D2ToolLoopFailurePort {
    fn fail_d2_tool_loop(
        &self,
        failure: D2ToolLoopFailureV1,
    ) -> Result<D2ToolLoopFailureResult, CommitError>;
}
