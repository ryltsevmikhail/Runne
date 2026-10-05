/// Durable dispatch rejection supplied to the store for independent revalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderPreEffectCancellationEvidence {
    pub dispatch_attempt_id: [u8; 16],
    pub cancellation_taskrun_version: u64,
}

/// Source1 factual terminal authenticated from the local encrypted journal.
/// `unknown_commitment` is an opaque accounting witness, never a finance digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderUnknownTerminalCancellationEvidence {
    pub dispatch_attempt_id: [u8; 16],
    pub disposition: runne_provider::ProviderTerminalDisposition,
    pub unknown_commitment: [u8; 32],
    pub cancellation_taskrun_version: u64,
}

/// Cancellation proof for a started attempt that never acquired provider admission.
/// The store independently proves the complete absence and exact TaskRun history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderNoAdmissionCancellationEvidence {
    pub cancellation_taskrun_version: u64,
}

/// Exact D2 claim identity used by the shared atomic Conversation cancellation writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D2ToolLoopCancellationEvidence {
    pub node_id: [u8; 16],
    pub node_epoch: u64,
    pub fence: u64,
    pub cancellation_taskrun_version: u64,
}

/// Same-node restart authority for a D2 attempt stopped before its first cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D2ToolLoopRestartEvidence {
    pub assignment: crate::ports::TaskRunAssignmentIdentity,
    pub recovery_epoch: u64,
    pub expected_taskrun_head: u64,
}

/// Atomic close of a started text attempt after cancellation won before admission.
#[derive(Debug, Clone)]
pub struct RejectTextGenerationAfterNoAdmissionCancellationCommit {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_started_taskrun_version: u64,
    pub evidence: ProviderNoAdmissionCancellationEvidence,
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    pub receipt: TextGenerationReceipt,
}

/// D2-specific cancellation evidence routed through the shared terminal writer.
#[derive(Debug, Clone)]
pub struct RejectTextGenerationAfterD2ToolLoopCancellationCommit {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_started_taskrun_version: u64,
    pub evidence: D2ToolLoopCancellationEvidence,
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    pub receipt: TextGenerationReceipt,
}

/// Atomic D2-only restart rejection when the TaskRun has no active loop cycle.
#[derive(Debug, Clone)]
pub struct RejectTextGenerationAfterD2ToolLoopRestartCommit {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_taskrun_version: u64,
    pub evidence: D2ToolLoopRestartEvidence,
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    pub receipt: TextGenerationReceipt,
}

/// Atomic close of a started text attempt after an exact pre-effect rejection.
#[derive(Debug, Clone)]
pub struct RejectTextGenerationAfterPreEffectCancellationCommit {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_started_taskrun_version: u64,
    pub evidence: ProviderPreEffectCancellationEvidence,
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    pub receipt: TextGenerationReceipt,
}

/// Atomic cancellation close backed by a separately authenticated Unknown fact.
#[derive(Debug, Clone)]
pub struct RejectTextGenerationAfterUnknownTerminalCancellationCommit {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_started_taskrun_version: u64,
    pub evidence: ProviderUnknownTerminalCancellationEvidence,
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    pub receipt: TextGenerationReceipt,
}

/// Distinct proof kinds accepted by the shared atomic cancellation writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCancellationProof {
    Terminal(ProviderTerminalCancellationEvidence),
    UnknownTerminal(ProviderUnknownTerminalCancellationEvidence),
    PreEffect(ProviderPreEffectCancellationEvidence),
    NoAdmission(ProviderNoAdmissionCancellationEvidence),
    /// D2 loop cancellation after validating every invocation's local stop state.
    D2ToolLoop(D2ToolLoopCancellationEvidence),
}

/// Internal shared request; proof kind remains explicit and closed.
#[derive(Debug, Clone)]
pub struct RejectTextGenerationAfterCancellationCommit {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_started_taskrun_version: u64,
    pub proof: ProviderCancellationProof,
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    pub receipt: TextGenerationReceipt,
}
