//! Worker-protocol catalog (PROTOCOL.md §Phase 1 backend worker
//! profile): the closed `backend_*` message set carried over a distinct
//! HKDF info domain (`WORKER_PURPOSE`). Engine `MessageV1` frames are
//! rejected on this channel. Every body binds the worker generation,
//! host generation and backend profile.

use crate::ProtocolBody;
use crate::cbor::Cbor;
use crate::error::ProtocolError;

/// Host→worker: bind the admitted artifact into backend state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerLoad {
    pub model_identity: String,
    pub load_id: [u8; 16],
    pub artifact_digest: String,
    pub byte_length: u64,
    pub load_fence: [u8; 16],
}

/// Bounded llama.cpp configuration derived from the admitted manifest;
/// never ambient or guessed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkerBackendConfig {
    pub context_max_tokens: u32,
    pub output_max_tokens: u32,
    pub gpu_layers: u32,
    pub threads: u32,
    pub seed: u32,
}

/// Closed worker error codes; unknown codes are rejected at decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerErrorCode {
    LoadFailed,
    DigestMismatch,
    LengthMismatch,
    ContextExceeded,
    Memory,
    Cancelled,
    Unsupported,
    Internal,
}

impl WorkerErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LoadFailed => "load_failed",
            Self::DigestMismatch => "digest_mismatch",
            Self::LengthMismatch => "length_mismatch",
            Self::ContextExceeded => "context_exceeded",
            Self::Memory => "memory",
            Self::Cancelled => "cancelled",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
        }
    }
}

impl std::str::FromStr for WorkerErrorCode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "load_failed" => Self::LoadFailed,
            "digest_mismatch" => Self::DigestMismatch,
            "length_mismatch" => Self::LengthMismatch,
            "context_exceeded" => Self::ContextExceeded,
            "memory" => Self::Memory,
            "cancelled" => Self::Cancelled,
            "unsupported" => Self::Unsupported,
            "internal" => Self::Internal,
            _ => return Err(()),
        })
    }
}

/// Closed stream-item kinds the worker may emit (text/usage/finish;
/// tool proposals never travel the worker channel).
pub const WORKER_ITEM_KINDS: [&str; 3] = ["text", "usage", "finish"];

/// Terminal reasons for `backend_terminal`.
pub const WORKER_TERMINAL_REASONS: [&str; 3] = ["stop", "cancelled", "error"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerFrameV1 {
    BackendLoad {
        worker_generation: [u8; 16],
        host_generation: [u8; 16],
        backend_profile: String,
        load: WorkerLoad,
        config: WorkerBackendConfig,
    },
    BackendLoaded {
        worker_generation: [u8; 16],
        host_generation: [u8; 16],
        backend_profile: String,
        load_id: [u8; 16],
        model_identity: String,
    },
    BackendInfer {
        worker_generation: [u8; 16],
        host_generation: [u8; 16],
        backend_profile: String,
        generation_id: [u8; 16],
        attempt_id: [u8; 16],
        stream_id: [u8; 16],
        /// Rendered prompt text (host-rendered, digest-bound upstream);
        /// the worker never re-renders or guesses templates.
        prompt: String,
    },
    BackendItem {
        worker_generation: [u8; 16],
        host_generation: [u8; 16],
        backend_profile: String,
        stream_id: [u8; 16],
        stream_sequence: u64,
        kind: String,
        payload: Vec<u8>,
    },
    BackendCancel {
        worker_generation: [u8; 16],
        host_generation: [u8; 16],
        backend_profile: String,
        cancel_id: [u8; 16],
    },
    BackendUnload {
        worker_generation: [u8; 16],
        host_generation: [u8; 16],
        backend_profile: String,
        load_id: [u8; 16],
    },
    BackendHealth {
        worker_generation: [u8; 16],
        host_generation: [u8; 16],
        backend_profile: String,
    },
    BackendTerminal {
        worker_generation: [u8; 16],
        host_generation: [u8; 16],
        backend_profile: String,
        stream_id: [u8; 16],
        reason: String,
        prompt_tokens: u64,
        output_tokens: u64,
    },
    BackendError {
        worker_generation: [u8; 16],
        host_generation: [u8; 16],
        backend_profile: String,
        code: WorkerErrorCode,
        detail: String,
    },
}

impl WorkerFrameV1 {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::BackendLoad { .. } => "backend_load",
            Self::BackendLoaded { .. } => "backend_loaded",
            Self::BackendInfer { .. } => "backend_infer",
            Self::BackendItem { .. } => "backend_item",
            Self::BackendCancel { .. } => "backend_cancel",
            Self::BackendUnload { .. } => "backend_unload",
            Self::BackendHealth { .. } => "backend_health",
            Self::BackendTerminal { .. } => "backend_terminal",
            Self::BackendError { .. } => "backend_error",
        }
    }

    /// Shared generation triple used by both ends to bind every frame
    /// to the exact worker/host generations and backend profile.
    pub fn triple(&self) -> ([u8; 16], [u8; 16], &str) {
        match self {
            Self::BackendLoad {
                worker_generation,
                host_generation,
                backend_profile,
                ..
            }
            | Self::BackendLoaded {
                worker_generation,
                host_generation,
                backend_profile,
                ..
            }
            | Self::BackendInfer {
                worker_generation,
                host_generation,
                backend_profile,
                ..
            }
            | Self::BackendItem {
                worker_generation,
                host_generation,
                backend_profile,
                ..
            }
            | Self::BackendCancel {
                worker_generation,
                host_generation,
                backend_profile,
                ..
            }
            | Self::BackendUnload {
                worker_generation,
                host_generation,
                backend_profile,
                ..
            }
            | Self::BackendHealth {
                worker_generation,
                host_generation,
                backend_profile,
            }
            | Self::BackendTerminal {
                worker_generation,
                host_generation,
                backend_profile,
                ..
            }
            | Self::BackendError {
                worker_generation,
                host_generation,
                backend_profile,
                ..
            } => (*worker_generation, *host_generation, backend_profile),
        }
    }

    /// Bounded detail: oversized `detail` payloads are protocol errors.
    pub const MAX_DETAIL_BYTES: usize = 512;
}

impl ProtocolBody for WorkerFrameV1 {
    fn type_name(&self) -> &'static str {
        WorkerFrameV1::type_name(self)
    }

    fn encode_body(&self) -> Cbor {
        crate::backend_codec::encode_worker_body(self)
    }

    fn decode_body(type_name: &str, body: &Cbor) -> Result<Self, ProtocolError> {
        crate::backend_codec::decode_worker_body(type_name, body)
    }
}
