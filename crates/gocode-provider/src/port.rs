use core::future::Future;
use core::pin::Pin;

use thiserror::Error;

use crate::{
    DispatchAttemptId, PreparedRequest, ProviderCall, ProviderCallDigestVersion,
    ProviderCapability, ProviderDispatchClaim, ProviderStreamId, ProviderStreamItem, StreamCursor,
    StreamError,
};

/// Runtime-neutral boxed future returned by adapter operations.
pub type ProviderFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Request to enter the adapter dispatch boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchRequest {
    prepared: PreparedRequest,
    claim: ProviderDispatchClaim,
}

impl DispatchRequest {
    /// Constructs a dispatch request only from the exact durable effect claim.
    pub fn new(
        prepared: PreparedRequest,
        claim: ProviderDispatchClaim,
    ) -> Result<Self, DispatchRequestError> {
        if claim.call_id != prepared.call().call_id()
            || claim.prepared_digest != *prepared.request_ref().as_bytes()
            || claim.render_digest != *prepared.render_digest()
        {
            return Err(DispatchRequestError::PreparedClaimMismatch);
        }
        if claim.fencing_token == 0
            || claim.provider_idempotency_key.is_empty()
            || claim.provider_idempotency_key.len() > 256
            || claim
                .provider_idempotency_key
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(DispatchRequestError::InvalidEffectBinding);
        }
        Ok(Self { prepared, claim })
    }

    /// Returns the prepared request.
    pub const fn prepared(&self) -> &PreparedRequest {
        &self.prepared
    }

    /// Returns the durable attempt identity.
    pub const fn attempt_id(&self) -> DispatchAttemptId {
        self.claim.attempt_id
    }

    /// Returns the stable non-secret provider-visible idempotency key.
    pub fn provider_idempotency_key(&self) -> &str {
        &self.claim.provider_idempotency_key
    }

    /// Returns the exact durable authority, reservations, fence, and evidence
    /// admitted before the adapter effect boundary.
    pub const fn claim(&self) -> &ProviderDispatchClaim {
        &self.claim
    }
}

/// Invalid adapter dispatch request metadata.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DispatchRequestError {
    /// Prepared request identity differs from the durable claim.
    #[error("provider dispatch claim does not bind the prepared request")]
    PreparedClaimMismatch,
    /// Permit, fence, reservations, or provider idempotency metadata is invalid.
    #[error("provider dispatch effect binding is invalid")]
    InvalidEffectBinding,
}

/// Request to cancel a transient provider stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRequest {
    stream_id: ProviderStreamId,
}

impl CancelRequest {
    /// Constructs a stream cancellation request.
    pub const fn new(stream_id: ProviderStreamId) -> Self {
        Self { stream_id }
    }

    /// Returns the stream identity.
    pub const fn stream_id(&self) -> ProviderStreamId {
        self.stream_id
    }
}

/// Request to reconcile one durable provider dispatch attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileRequest {
    attempt_id: DispatchAttemptId,
}

impl ReconcileRequest {
    /// Constructs a reconciliation request.
    pub const fn new(attempt_id: DispatchAttemptId) -> Self {
        Self { attempt_id }
    }

    /// Returns the attempt identity.
    pub const fn attempt_id(&self) -> DispatchAttemptId {
        self.attempt_id
    }
}

/// Prepare failure before any external effect.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PrepareError {
    /// A required capability is absent.
    #[error("unsupported provider capability: {0:?}")]
    UnsupportedCapability(ProviderCapability),
    /// Deterministic rendering failed.
    #[error("provider render failed: {0}")]
    Render(String),
    /// Exact credential-free rendered bytes are empty or exceed their bound.
    #[error("provider rendered request violates its byte bound")]
    RenderedRequestBound,
    /// Adapter cannot reconstruct the requested historical digest contract.
    #[error("provider digest version is unsupported for recovery: {0:?}")]
    UnsupportedDigestVersion(ProviderCallDigestVersion),
}

/// Dispatch/control boundary failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DispatchError {
    /// Adapter proves the external effect boundary was not crossed.
    #[error("provider dispatch was rejected before external effect")]
    RejectedBeforeEffect(crate::ProviderPreEffectRejection),
    /// Dispatch began but remote acceptance cannot be proven or excluded.
    #[error("provider dispatch may have reached the external provider")]
    MaybeDispatched,
    /// Attempt identity conflicts with an existing prepared request.
    #[error("provider dispatch attempt conflicts with existing request")]
    AttemptConflict,
    /// Stream identity does not exist.
    #[error("provider stream was not found")]
    StreamNotFound,
}

/// Local cancellation disposition; it is not remote effect evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelDisposition {
    /// Cancellation was requested locally.
    Requested,
    /// The same cancellation was already requested.
    AlreadyRequested,
}

/// Explicit adapter reconciliation disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationDisposition {
    /// Evidence proves no request was dispatched.
    Absent,
    /// Evidence proves the exact effect settled.
    Settled,
    /// The external effect remains ambiguous.
    Uncertain,
}

/// Provider-neutral adapter boundary.
pub trait ProviderPort: Send + Sync {
    /// Deterministically prepares a non-secret request without dispatch.
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError>;

    /// Reconstructs an exact historical prepared request for durable replay.
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        digest_version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError>;

    /// Dispatches an already admitted request.
    fn dispatch(
        &self,
        request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>>;

    /// Reads the next normalized stream event.
    fn next<'a>(
        &'a self,
        stream: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>>;

    /// Requests adapter cancellation.
    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>>;

    /// Probes settlement without inferring success from transport state.
    fn reconcile(
        &self,
        request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>>;
}
