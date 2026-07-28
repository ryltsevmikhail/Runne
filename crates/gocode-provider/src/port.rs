use core::future::Future;
use core::pin::Pin;

use thiserror::Error;

use crate::{
    DispatchAttemptId, ProviderCall, ProviderCapability, ProviderStreamId, ProviderStreamItem,
    StreamCursor, StreamError, canonical_provider_call_digest,
};

/// Runtime-neutral boxed future returned by adapter operations.
pub type ProviderFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Content-addressed reference to a prepared non-secret request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PreparedRequestRef([u8; 32]);

impl PreparedRequestRef {
    /// Returns the reference digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Immutable prepared request metadata. Credential material is absent.
#[derive(Debug, Clone, PartialEq)]
pub struct PreparedRequest {
    request_ref: PreparedRequestRef,
    call: ProviderCall,
}

impl PreparedRequest {
    /// Deterministically constructs a credential-free prepared request.
    pub fn from_call(call: &ProviderCall) -> Result<Self, PrepareError> {
        let digest = canonical_provider_call_digest(call)
            .map_err(|error| PrepareError::Render(error.to_string()))?;
        Ok(Self {
            request_ref: PreparedRequestRef(*digest.as_bytes()),
            call: call.clone(),
        })
    }

    /// Returns the content-addressed request reference.
    pub const fn request_ref(&self) -> PreparedRequestRef {
        self.request_ref
    }

    /// Returns the normalized source call.
    pub const fn call(&self) -> &ProviderCall {
        &self.call
    }
}

/// Request to enter the adapter dispatch boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchRequest {
    prepared: PreparedRequest,
    attempt_id: DispatchAttemptId,
}

impl DispatchRequest {
    /// Constructs a dispatch request for an exact prepared request and attempt.
    pub const fn new(prepared: PreparedRequest, attempt_id: DispatchAttemptId) -> Self {
        Self {
            prepared,
            attempt_id,
        }
    }

    /// Returns the prepared request.
    pub const fn prepared(&self) -> &PreparedRequest {
        &self.prepared
    }

    /// Returns the durable attempt identity.
    pub const fn attempt_id(&self) -> DispatchAttemptId {
        self.attempt_id
    }
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
}

/// Dispatch/control boundary failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DispatchError {
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
