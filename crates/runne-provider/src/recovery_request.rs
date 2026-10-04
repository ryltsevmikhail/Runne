use crate::{
    ProviderRecoveryAttemptIdentity, ProviderRecoveryBinding, RemoteResponseId, RemoteStreamCursor,
};

/// Historical TaskRun, attempt, profile, and remote response identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRecoveryRequest {
    binding: ProviderRecoveryBinding,
    response_id: RemoteResponseId,
    identity: Option<ProviderRecoveryAttemptIdentity>,
}

/// Request to resume one exact remote response after the last persisted event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderResumeRequest {
    response: ProviderRecoveryRequest,
    after: RemoteStreamCursor,
}

impl ProviderResumeRequest {
    /// Constructs a resume request for the same response and durable attempt.
    pub const fn new(response: ProviderRecoveryRequest, after: RemoteStreamCursor) -> Self {
        Self { response, after }
    }

    /// Returns the exact response identity.
    pub const fn response(&self) -> &ProviderRecoveryRequest {
        &self.response
    }
    /// Returns the last durably observed sequence.
    pub const fn after(&self) -> RemoteStreamCursor {
        self.after
    }
}

impl ProviderRecoveryRequest {
    /// Constructs identity-only metadata; this does not authorize a remote operation.
    pub const fn new(binding: ProviderRecoveryBinding, response_id: RemoteResponseId) -> Self {
        Self {
            binding,
            response_id,
            identity: None,
        }
    }

    /// Constructs a request with exact historical provider and admission metadata.
    pub fn new_exact(
        binding: ProviderRecoveryBinding,
        response_id: RemoteResponseId,
        identity: ProviderRecoveryAttemptIdentity,
    ) -> Result<Self, crate::ProviderRecoveryError> {
        if binding.profile_digest() == [0; 32]
            || binding.profile_digest() != *identity.profile_digest()
        {
            return Err(crate::ProviderRecoveryError::InvalidIdentity);
        }
        Ok(Self {
            binding,
            response_id,
            identity: Some(identity),
        })
    }

    /// Returns the exact local effect identity.
    pub const fn binding(&self) -> ProviderRecoveryBinding {
        self.binding
    }
    /// Returns the provider response ID.
    pub fn response_id(&self) -> &RemoteResponseId {
        &self.response_id
    }
    /// Returns exact admission metadata when loaded from trusted durable state.
    pub const fn identity(&self) -> Option<&ProviderRecoveryAttemptIdentity> {
        self.identity.as_ref()
    }
}
