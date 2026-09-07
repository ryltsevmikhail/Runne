//! Provider-local errors. Debug names are contract surface.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderError {
    Broker(runne_engine_broker::BrokerError),
    UnknownManifest,
    ArtifactNotInstalled,
    /// No ancillary fd arrived with a frame that requires one.
    FdMissing,
    /// More than one ancillary fd arrived with a single frame.
    FdDuplicate,
    LengthMismatch,
    Store(runne_model_store::StoreError),
    /// Frame metadata does not match the grant binding.
    FrameMismatch,
    AttemptConflict,
    MalformedStream,
    Host(runne_inference_host::HostError),
    Sampling(crate::sampling_error::SamplingError),
    Structured(crate::structured::StructuredError),
    Resource(crate::resource_quote::ResourceError),
    QueueFull,
    QueueClosed,
    OneLoadedModelConflict,
    /// Typed pre-dispatch context breach; sanitized counts only.
    ContextExceeded {
        quoted_tokens: u64,
        context_limit: u64,
        reserved_output_tokens: u64,
    },
    TokenizerQuote(String),
    ToolProtocol(crate::tool_protocol::ToolProtocolError),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Broker(e) => write!(f, "broker: {e:?}"),
            Self::UnknownManifest => write!(f, "unknown manifest digest"),
            Self::ArtifactNotInstalled => write!(f, "artifact not installed"),
            Self::FdMissing => write!(f, "required ancillary fd missing"),
            Self::FdDuplicate => write!(f, "duplicate ancillary fd"),
            Self::LengthMismatch => write!(f, "artifact length mismatch"),
            Self::Store(e) => write!(f, "store: {e:?}"),
            Self::FrameMismatch => write!(f, "frame metadata mismatch"),
            Self::AttemptConflict => write!(f, "attempt binding conflict"),
            Self::MalformedStream => write!(f, "malformed stream event"),
            Self::Host(e) => write!(f, "host: {e:?}"),
            Self::Sampling(e) => write!(f, "sampling: {e}"),
            Self::Structured(e) => write!(f, "structured output: {e}"),
            Self::Resource(e) => write!(f, "resource: {e}"),
            Self::QueueFull => write!(f, "dispatch queue full"),
            Self::QueueClosed => write!(f, "dispatch queue closed"),
            Self::OneLoadedModelConflict => {
                write!(f, "another model is loaded; no implicit eviction")
            }
            Self::ContextExceeded {
                quoted_tokens,
                context_limit,
                reserved_output_tokens,
            } => write!(
                f,
                "context exceeded: quoted {quoted_tokens} over {} - {reserved_output_tokens} reserved of {context_limit}",
                context_limit
            ),
            Self::TokenizerQuote(e) => write!(f, "tokenizer quote: {e}"),
            Self::ToolProtocol(e) => write!(f, "tool protocol: {e}"),
        }
    }
}

impl std::error::Error for ProviderError {}

impl From<runne_engine_broker::BrokerError> for ProviderError {
    fn from(e: runne_engine_broker::BrokerError) -> Self {
        Self::Broker(e)
    }
}

impl From<runne_model_store::StoreError> for ProviderError {
    fn from(e: runne_model_store::StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<runne_inference_host::HostError> for ProviderError {
    fn from(e: runne_inference_host::HostError) -> Self {
        Self::Host(e)
    }
}
