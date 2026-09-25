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
}
