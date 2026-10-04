use crate::{DispatchAttemptId, ProviderFuture, ProviderUsage};
use runne_domain::id::{AttemptId, TaskRunId};
use thiserror::Error;

/// Independently declared remote controls supported by an adapter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProviderRecoveryCapabilities {
    /// The adapter can query one exact remote response.
    pub status_check: bool,
    /// The adapter can resume an exact response stream after a cursor.
    pub stream_resume: bool,
    /// The adapter can request cancellation of one exact remote response.
    pub remote_cancel: bool,
}

/// Local identities that bind remote recovery to one admitted effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderRecoveryBinding {
    /// Durable TaskRun identity.
    task_run_id: TaskRunId,
    /// Durable TaskRun attempt identity.
    task_attempt_id: AttemptId,
    /// Durable provider dispatch attempt identity.
    provider_attempt_id: DispatchAttemptId,
    /// Immutable selected provider profile digest.
    profile_digest: [u8; 32],
}

impl ProviderRecoveryBinding {
    /// Constructs the full durable identity for one profile-bound attempt.
    pub fn new(
        task_run_id: TaskRunId,
        task_attempt_id: AttemptId,
        provider_attempt_id: DispatchAttemptId,
        profile_digest: [u8; 32],
    ) -> Result<Self, ProviderRecoveryError> {
        if task_run_id.as_bytes() == &[0; 16]
            || task_attempt_id.as_bytes() == &[0; 16]
            || provider_attempt_id.as_bytes() == &[0; 16]
            || profile_digest == [0; 32]
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        Ok(Self {
            task_run_id,
            task_attempt_id,
            provider_attempt_id,
            profile_digest,
        })
    }

    /// Returns the TaskRun identity.
    pub const fn task_run_id(self) -> TaskRunId {
        self.task_run_id
    }
    /// Returns the TaskRun attempt identity.
    pub const fn task_attempt_id(self) -> AttemptId {
        self.task_attempt_id
    }
    /// Returns the provider dispatch attempt identity.
    pub const fn provider_attempt_id(self) -> DispatchAttemptId {
        self.provider_attempt_id
    }
    /// Returns the selected immutable profile digest.
    pub const fn profile_digest(self) -> [u8; 32] {
        self.profile_digest
    }
}

/// Bounded opaque provider response identity, distinct from diagnostic request IDs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RemoteResponseId(String);

impl RemoteResponseId {
    /// Maximum accepted response ID bytes.
    pub const MAX_BYTES: usize = 256;

    /// Constructs a nonempty printable ASCII provider response ID.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderRecoveryError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > Self::MAX_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        Ok(Self(value))
    }

    /// Returns the opaque response identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Provider stream sequence cursor used only for remote resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RemoteStreamCursor(u64);

impl RemoteStreamCursor {
    /// Constructs a cursor from an observed provider event sequence.
    pub const fn new(sequence: u64) -> Self {
        Self(sequence)
    }

    /// Returns the last observed sequence.
    pub const fn sequence(self) -> u64 {
        self.0
    }
}

/// Explicit remote response outcome; unknown remains distinct from pending and terminal.
#[derive(Clone, PartialEq, Eq)]
pub enum ProviderRemoteResponseStatus {
    /// Provider accepted the work and has not produced a terminal outcome.
    Pending,
    /// Provider explicitly reported successful completion.
    Completed {
        /// Provider-reported billable usage, when returned.
        usage: Option<ProviderUsage>,
    },
    /// Provider explicitly reported failure.
    Failed {
        /// Bounded provider failure code, without diagnostic message text.
        code: Option<String>,
        /// Provider-reported usage, when returned.
        usage: Option<ProviderUsage>,
    },
    /// Provider explicitly reported incomplete work.
    Incomplete {
        /// Bounded provider incomplete reason.
        reason: Option<String>,
        /// Provider-reported usage, when returned.
        usage: Option<ProviderUsage>,
    },
    /// Provider explicitly reported cancellation.
    Cancelled {
        /// Provider-reported usage, when returned.
        usage: Option<ProviderUsage>,
    },
    /// Status cannot be established from available evidence.
    Unknown,
}

/// Remote recovery API error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderRecoveryError {
    /// The adapter does not support this independent remote control.
    #[error("provider recovery capability is unsupported")]
    Unsupported,
    /// The response identity or returned recovery data violated its bound.
    #[error("provider recovery data is invalid")]
    InvalidIdentity,
    /// The remote operation could not establish a result.
    #[error("provider recovery operation is unavailable")]
    Unavailable,
}

/// Async durable sink for an early remote response ID.
pub trait ProviderResponseIdentityCommitter: Send + Sync {
    /// Persists exact credential-free rendered request bytes before create.
    fn persist_request<'a>(
        &'a self,
        _binding: ProviderRecoveryBinding,
        _identity: &'a crate::ProviderRecoveryAttemptIdentity,
        _rendered_request: &'a [u8],
    ) -> ProviderFuture<'a, Result<(), ProviderRecoveryError>> {
        Box::pin(async { Err(ProviderRecoveryError::Unsupported) })
    }

    /// Persists the response ID before the adapter exposes subsequent stream events.
    fn commit<'a>(
        &'a self,
        binding: ProviderRecoveryBinding,
        response_id: &'a RemoteResponseId,
    ) -> ProviderFuture<'a, Result<(), ProviderRecoveryError>>;

    /// Persists the response from one proof-backed status or cancellation operation.
    fn persist_remote_check<'a>(
        &'a self,
        _check: &'a crate::ProviderRemoteCheck,
    ) -> ProviderFuture<'a, Result<(), ProviderRecoveryError>> {
        Box::pin(async { Err(ProviderRecoveryError::Unsupported) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_response_identity_is_bounded_and_printable() {
        assert!(RemoteResponseId::new("resp_1").is_ok());
        assert!(RemoteResponseId::new("").is_err());
        assert!(RemoteResponseId::new("resp\n1").is_err());
        assert!(RemoteResponseId::new("x".repeat(257)).is_err());
    }

    #[test]
    fn recovery_binding_requires_a_profile_and_keeps_attempt_scopes_distinct() {
        let run = TaskRunId::from_bytes([1; 16]);
        let task_attempt = AttemptId::from_bytes([2; 16]);
        let provider_attempt = DispatchAttemptId::from_bytes([3; 16]);
        assert!(
            ProviderRecoveryBinding::new(run, task_attempt, provider_attempt, [0; 32]).is_err()
        );
        let binding =
            ProviderRecoveryBinding::new(run, task_attempt, provider_attempt, [4; 32]).unwrap();
        assert_eq!(binding.task_run_id(), run);
        assert_eq!(binding.task_attempt_id(), task_attempt);
        assert_eq!(binding.provider_attempt_id(), provider_attempt);
        assert_eq!(binding.profile_digest(), [4; 32]);
    }

    #[test]
    fn recovery_binding_rejects_empty_local_and_provider_identities() {
        let task_run = TaskRunId::from_bytes([1; 16]);
        let task_attempt = AttemptId::from_bytes([2; 16]);
        let provider_attempt = DispatchAttemptId::from_bytes([3; 16]);
        assert!(
            ProviderRecoveryBinding::new(
                TaskRunId::from_bytes([0; 16]),
                task_attempt,
                provider_attempt,
                [4; 32]
            )
            .is_err()
        );
        assert!(
            ProviderRecoveryBinding::new(
                task_run,
                AttemptId::from_bytes([0; 16]),
                provider_attempt,
                [4; 32]
            )
            .is_err()
        );
        assert!(
            ProviderRecoveryBinding::new(
                task_run,
                task_attempt,
                DispatchAttemptId::from_bytes([0; 16]),
                [4; 32]
            )
            .is_err()
        );
    }

    #[test]
    fn remote_response_identity_debug_is_redacted() {
        let identity = RemoteResponseId::new("resp_private_123").unwrap();
        assert!(!format!("{identity:?}").contains("private"));
    }
}
