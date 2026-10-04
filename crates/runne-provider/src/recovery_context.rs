use std::sync::Arc;
use zeroize::Zeroizing;

use crate::{
    DispatchAttemptId, ProviderDispatchClaim, ProviderFuture, ProviderRecoveryAttemptIdentity,
    ProviderRecoveryBinding, ProviderRecoveryError, ProviderRecoveryRequest,
    ProviderRemoteOperationProof, ProviderResponseIdentityCommitter, RemoteResponseId,
};

/// Separately authorized remote operation; never represents create dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRecoveryOperation {
    /// Read status for one exact persisted response.
    StatusCheck,
    /// Resume the exact persisted event stream after a sequence cursor.
    StreamResume,
    /// Request remote cancellation for the exact persisted response.
    RemoteCancel,
}

/// Fresh runtime authority for recovery; implementations validate durable binding and current fence.
pub trait ProviderRecoveryControlAuthorizer: Send + Sync {
    /// Validates current authority and materializes its credential and one-use proof together.
    fn authorize_and_materialize<'a>(
        &'a self,
        request: &'a ProviderRecoveryRequest,
        operation: ProviderRecoveryOperation,
    ) -> ProviderFuture<'a, Result<ProviderRecoveryAuthorization, ProviderRecoveryError>>;
}

/// Freshly materialized credential paired with a store-issued, one-use operation proof.
pub struct ProviderRecoveryAuthorization {
    credential: Zeroizing<Vec<u8>>,
    proof: ProviderRemoteOperationProof,
}

impl ProviderRecoveryAuthorization {
    /// Constructs an authorization returned by a trusted current-authority issuer.
    pub fn new(
        credential: Zeroizing<Vec<u8>>,
        proof: ProviderRemoteOperationProof,
    ) -> Result<Self, ProviderRecoveryError> {
        if credential.is_empty() {
            return Err(ProviderRecoveryError::Unavailable);
        }
        Ok(Self { credential, proof })
    }

    /// Returns the short-lived credential only for the immediate transport operation.
    pub fn credential(&self) -> &Zeroizing<Vec<u8>> {
        &self.credential
    }

    /// Returns proof metadata that must be consumed by the durable result writer.
    pub const fn proof(&self) -> &ProviderRemoteOperationProof {
        &self.proof
    }
}

/// Full durable attempt binding plus its encrypted-store response-ID commit sink.
pub struct ProviderRecoveryDispatchContext {
    binding: ProviderRecoveryBinding,
    identity: Option<ProviderRecoveryAttemptIdentity>,
    committer: Arc<dyn ProviderResponseIdentityCommitter>,
}

impl ProviderRecoveryDispatchContext {
    /// Constructs context supplied by a trusted durable runtime lookup.
    pub fn new(
        binding: ProviderRecoveryBinding,
        committer: Arc<dyn ProviderResponseIdentityCommitter>,
    ) -> Self {
        Self {
            binding,
            identity: None,
            committer,
        }
    }

    /// Constructs context with exact trusted metadata loaded from durable admission.
    pub fn new_exact(
        binding: ProviderRecoveryBinding,
        identity: ProviderRecoveryAttemptIdentity,
        committer: Arc<dyn ProviderResponseIdentityCommitter>,
    ) -> Self {
        Self {
            binding,
            identity: Some(identity),
            committer,
        }
    }

    /// Returns the full historical identity that must match the create claim.
    pub const fn binding(&self) -> ProviderRecoveryBinding {
        self.binding
    }

    /// Returns exact provider and historical launch metadata when available.
    pub const fn identity(&self) -> Option<&ProviderRecoveryAttemptIdentity> {
        self.identity.as_ref()
    }

    /// Builds the exact operation request from this trusted durable context.
    pub fn recovery_request(
        &self,
        response_id: RemoteResponseId,
    ) -> Result<ProviderRecoveryRequest, ProviderRecoveryError> {
        let identity = self
            .identity
            .clone()
            .ok_or(ProviderRecoveryError::InvalidIdentity)?;
        ProviderRecoveryRequest::new_exact(self.binding, response_id, identity)
    }

    /// Persists the first validated response identity before later events are exposed.
    pub async fn commit_response_id(
        &self,
        response_id: &RemoteResponseId,
    ) -> Result<(), ProviderRecoveryError> {
        self.committer.commit(self.binding, response_id).await
    }

    /// Persists the exact request before the adapter attempts its first send.
    pub async fn persist_request(
        &self,
        rendered_request: &[u8],
    ) -> Result<(), ProviderRecoveryError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or(ProviderRecoveryError::InvalidIdentity)?;
        if rendered_request.is_empty() || rendered_request.len() > 524_288 {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        self.committer
            .persist_request(self.binding, identity, rendered_request)
            .await
    }

    /// Persists one fresh status/cancel observation through the exact dispatch sink.
    pub async fn persist_remote_check(
        &self,
        check: &crate::ProviderRemoteCheck,
    ) -> Result<(), ProviderRecoveryError> {
        if check.binding() != self.binding || check.operation_proof().is_none() {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        self.committer.persist_remote_check(check).await
    }

    /// Verifies the adapter-facing part of a dispatch binding.
    pub fn matches_claim(&self, attempt: DispatchAttemptId, profile_digest: [u8; 32]) -> bool {
        self.binding.provider_attempt_id() == attempt
            && self.binding.profile_digest() == profile_digest
    }
}

/// Resolves one exact provider dispatch to a sealed full TaskRun recovery binding.
pub trait ProviderRecoveryDispatchContextProvider: Send + Sync {
    /// Resolves a fresh pre-create context from a durable admitted dispatch.
    /// This path has no response ID and must only persist the request before one create.
    fn for_new_dispatch<'a>(
        &'a self,
        _claim: &'a ProviderDispatchClaim,
        _provider_id: &'a crate::ProviderId,
        _credential_realm: &'a crate::ProviderId,
        _profile_id: &'a str,
    ) -> ProviderFuture<'a, Result<ProviderRecoveryDispatchContext, ProviderRecoveryError>> {
        Box::pin(async { Err(ProviderRecoveryError::Unsupported) })
    }

    /// Reopens an exact request intent already sealed by the common runtime
    /// send fence. This does not authorize another request persistence or
    /// create; it only supplies the early response-ID commit sink.
    fn for_persisted_new_dispatch<'a>(
        &'a self,
        _claim: &'a ProviderDispatchClaim,
        _provider_id: &'a crate::ProviderId,
        _credential_realm: &'a crate::ProviderId,
        _profile_id: &'a str,
        _rendered_request: &'a [u8],
    ) -> ProviderFuture<'a, Result<ProviderRecoveryDispatchContext, ProviderRecoveryError>> {
        Box::pin(async { Err(ProviderRecoveryError::Unsupported) })
    }

    /// Loads the full historical binding and durable identity sink for one claimed dispatch.
    fn for_dispatch<'a>(
        &'a self,
        claim: &'a ProviderDispatchClaim,
    ) -> ProviderFuture<'a, Result<ProviderRecoveryDispatchContext, ProviderRecoveryError>>;
}
