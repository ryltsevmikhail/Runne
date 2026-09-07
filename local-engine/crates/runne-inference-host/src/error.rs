//! Host errors (sanitized, typed; Debug names are contract surface).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostError {
    Protocol(runne_inference_protocol::ProtocolError),
    IntegrityViolation,
    ProtocolMismatch,
    ModelNotLoaded,
    ModelAlreadyActive,
    ArtifactGrantInvalid,
    CorruptModel,
    FdMissing,
    FdDuplicate,
    FdCloexecMissing,
    GenerationMismatch,
    AttemptConflict,
    MalformedStream,
    InvalidState,
    ShaMismatch,
    /// Bounded native worker failure (typed protocol code + detail).
    Worker {
        code: runne_inference_protocol::WorkerErrorCode,
        detail: String,
    },
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Protocol(e) => return write!(f, "protocol: {e:?}"),
            Self::IntegrityViolation => "integrity violation; session closed",
            Self::ProtocolMismatch => "no compatible protocol version",
            Self::ModelNotLoaded => "no model loaded for this operation",
            Self::ModelAlreadyActive => "model already active (one-model policy)",
            Self::ArtifactGrantInvalid => "artifact grant/frame binding invalid",
            Self::CorruptModel => "model bytes failed bounded inspection",
            Self::FdMissing => "required ancillary fd missing",
            Self::FdDuplicate => "duplicate ancillary fd",
            Self::FdCloexecMissing => "received fd lacks close-on-exec",
            Self::GenerationMismatch => "generation/attempt identity mismatch",
            Self::AttemptConflict => "attempt binding conflict",
            Self::MalformedStream => "malformed stream event",
            Self::InvalidState => "operation invalid in current state",
            Self::ShaMismatch => "declared sha256 malformed",
            Self::Worker { code, .. } => return write!(f, "worker: {}", code.as_str()),
        };
        write!(f, "{text}")
    }
}

impl std::error::Error for HostError {}

impl From<runne_inference_protocol::ProtocolError> for HostError {
    fn from(e: runne_inference_protocol::ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
