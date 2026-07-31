use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Secret materializer used only after durable effect admission.
pub trait SecretMaterializer: Send + Sync {
    /// Materializes one credential into zeroized memory.
    fn materialize(&self) -> Result<Zeroizing<Vec<u8>>, TransportError>;
}

/// Exact HTTP request with all ambient behavior disabled.
pub struct HttpTransportRequest {
    /// HTTPS origin.
    pub origin: String,
    /// Exact request path.
    pub path: String,
    /// Serialized bounded body.
    pub body: Vec<u8>,
    /// Stable non-secret key used by the remote provider for effect deduplication.
    pub provider_idempotency_key: String,
    /// Ephemeral authorization bytes. Diagnostics must never include them.
    pub authorization: Zeroizing<Vec<u8>>,
    /// Redirect following is always false.
    pub follow_redirects: bool,
    /// Ambient proxy/environment discovery is always false.
    pub use_ambient_proxy: bool,
}

impl Drop for HttpTransportRequest {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// Sanitized bounded transport response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTransportResponse {
    /// Exact response origin.
    pub origin: String,
    /// Exact response path.
    pub path: String,
    /// Synthetic normalized response body.
    pub body: Vec<u8>,
}

/// Bounded HTTP transport abstraction.
pub trait HttpTransport: Send + Sync {
    /// Sends one request with redirects and ambient proxy discovery disabled.
    fn send(&self, request: HttpTransportRequest) -> Result<HttpTransportResponse, TransportError>;
}

/// Sanitized transport error without credential/body data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransportError {
    /// Transport is unavailable.
    #[error("provider transport unavailable")]
    Unavailable,
    /// Response did not preserve exact origin/path.
    #[error("provider transport origin mismatch")]
    OriginMismatch,
    /// Body or frame exceeded its profile bound.
    #[error("provider transport bound exceeded")]
    BoundExceeded,
    /// Response shape was not recognized.
    #[error("provider response is invalid")]
    InvalidResponse,
}
