use runne_provider::{ProviderCallDigestVersion, ProviderCallId};

/// Immutable provider request facts to bind to one live TaskRun assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTaskRunProviderRequest {
    pub call_id: ProviderCallId,
    pub call_digest_version: ProviderCallDigestVersion,
    pub prepared_digest: [u8; 32],
    pub render_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub provider_idempotency_key: String,
}

/// Complete store transaction input for a pre-effect provider binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindPreparedTaskRunProviderEffect {
    pub identity: TaskRunAssignmentIdentity,
    pub expected_claim_version: u64,
    pub prepared: PreparedTaskRunProviderRequest,
}

/// Exact preceding D2 effect whose stored result permits the next provider round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskRunProviderToolResultRef {
    pub attempt_id: AttemptId,
    pub cycle_id: CycleId,
    pub proposal_index: u32,
    pub semantic_digest: IntegrityDigest,
    pub result_digest: IntegrityDigest,
}

/// Internal D2 admission binds each bounded continuation to its current TaskRun head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindPreparedTaskRunProviderRoundEffect {
    pub identity: TaskRunAssignmentIdentity,
    pub original_claim_version: u64,
    pub current_taskrun_head: u64,
    pub round_index: u32,
    pub previous_tool_result: Option<TaskRunProviderToolResultRef>,
    pub prepared: PreparedTaskRunProviderRequest,
}

/// Binding records establish identity only; they do not authorize effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRunProviderBindingResult {
    Bound,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRunProviderBindingError {
    StaleAssignment,
    StaleVersion,
    LeaseExpired,
    NodeUnavailable,
    NotPrepared,
    IdempotencyConflict,
    CorruptData,
    Unavailable,
}

/// Atomically binds immutable provider request metadata to an exact live claim.
/// This is pre-effect evidence only; provider effect start must revalidate it.
pub trait TaskRunProviderBindingPort {
    fn bind_prepared_taskrun_provider_effect(
        &self,
        request: BindPreparedTaskRunProviderEffect,
    ) -> Result<TaskRunProviderBindingResult, TaskRunProviderBindingError>;

    fn bind_prepared_taskrun_provider_round_effect(
        &self,
        request: BindPreparedTaskRunProviderRoundEffect,
    ) -> Result<TaskRunProviderBindingResult, TaskRunProviderBindingError>;

    fn verify_prepared_taskrun_provider_round_effect(
        &self,
        request: BindPreparedTaskRunProviderRoundEffect,
    ) -> Result<(), TaskRunProviderBindingError>;
}
