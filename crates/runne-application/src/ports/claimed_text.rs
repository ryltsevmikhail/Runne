use runne_domain::message::MessageText;

/// Atomic user-message start bound to an already claimed TaskRun.
#[derive(Debug, Clone)]
pub struct BeginClaimedTextGenerationCommit {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_taskrun_version: u64,
    pub submitted_prompt: MessageText,
    pub assignment: TaskRunAssignmentIdentity,
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    pub receipt: TextGenerationReceipt,
}
