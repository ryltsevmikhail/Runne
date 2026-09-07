//! Local `ProviderPort` surface (structural mirror of the product's
//! `runne-provider` port; the binding to the product crate happens at
//! application composition per R3). Effect-free prepare, admitted
//! dispatch, ordered stream, terminal usage, cancel, reconcile.

use crate::error::ProviderError;
use crate::prepared::PreparedRequest;

/// Normalized call handed to prepare. Digest-bound; no credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCall {
    pub call_id: [u8; 16],
    pub model_ref: String,
    pub manifest_digest: String,
    pub max_output_tokens: u32,
    pub inputs: Vec<(String, String)>, // (role, text)
    pub required_capabilities: Vec<String>,
    /// Provider-neutral extension map (namespaced; the engine owns
    /// only `local-engine.*` keys).
    pub extension: serde_json::Value,
}

/// Stream item kinds the adapter normalizes (text/usage/finish only;
/// tool proposals travel the ToolGateway path, never this stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamItem {
    Text {
        seq: u64,
        text: String,
    },
    Usage {
        seq: u64,
        input_tokens: u64,
        output_tokens: u64,
    },
    Finished {
        seq: u64,
        reason: String,
    },
}

/// Terminal reconciliation dispositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciliation {
    Absent,
    Settled,
    Uncertain,
}

/// One-time dispatch claim handed to the adapter by the application
/// coordinator (already admitted; the adapter never self-admits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchRequest {
    pub attempt_id: [u8; 16],
    pub generation_id: [u8; 16],
    pub stream_id: [u8; 16],
    pub prepared_call_id: [u8; 16],
    /// Exact artifact digest bound to the admitted permit.
    pub artifact_digest: String,
}

/// Streaming state exposed by the adapter (ordered, attempt-scoped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStream {
    pub stream_id: [u8; 16],
    pub cursor: u64,
    pub items: Vec<StreamItem>,
    pub finished: bool,
}

/// Local cancel receipt disposition (Plan Task 10): `Requested` on the
/// first accepted cancel, `AlreadyRequested` for duplicates. Terminal
/// proof arrives later as an authenticated terminal stream item — a
/// receipt is never completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelDisposition {
    Requested,
    AlreadyRequested,
}

/// The port surface. `prepare` is deterministic and effect-free;
/// `dispatch` accepts only the exact prepared call already admitted.
pub trait ProviderPort: Send + Sync {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, ProviderError>;
    fn dispatch(
        &mut self,
        prepared: &PreparedRequest,
        request: &DispatchRequest,
    ) -> Result<ProviderStream, ProviderError>;
    fn next(
        &mut self,
        stream_id: &[u8; 16],
        cursor: u64,
    ) -> Result<Option<StreamItem>, ProviderError>;
    /// Local receipt only; completion is terminal evidence.
    fn cancel(&mut self, stream_id: &[u8; 16]) -> Result<CancelDisposition, ProviderError>;
    fn reconcile(&mut self, attempt_id: &[u8; 16]) -> Result<Reconciliation, ProviderError>;
}
