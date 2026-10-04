use runne_provider::ProviderTerminalDisposition;

/// Exact locally durable provider settlement validated by canonical recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderTerminalCancellationEvidence {
    pub dispatch_attempt_id: [u8; 16],
    pub disposition: ProviderTerminalDisposition,
    pub settlement_digest: [u8; 32],
    pub cancellation_taskrun_version: u64,
}

/// Atomic rejection of a started text receipt after a winning cancellation.
#[derive(Debug, Clone)]
pub struct RejectTextGenerationAfterTerminalCancellationCommit {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_started_taskrun_version: u64,
    pub evidence: ProviderTerminalCancellationEvidence,
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    pub receipt: TextGenerationReceipt,
}
