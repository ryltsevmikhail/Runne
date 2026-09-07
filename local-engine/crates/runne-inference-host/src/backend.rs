//! Backend-neutral host port: load, generate, cancel, unload. Backends
//! implement this trait; the host enforces state and identity, backends
//! never see paths or ambient authority.

use crate::error::HostError;
use runne_inference_protocol::MessageV1;
use std::fs::File;
use std::path::PathBuf;

/// A model image handed to the backend through a read-only descriptor.
pub struct LoadRequest {
    pub model_identity: String,
    pub load_id: [u8; 16],
    /// Pre-opened read-only artifact handle (regular file).
    pub artifact: File,
    /// Exact admitted artifact digest the descriptor must match.
    pub artifact_digest: String,
    /// Exact admitted artifact length the descriptor must match.
    pub byte_length: u64,
    /// Deterministic backend configuration (fake backend consumes this).
    pub config: BackendConfig,
}

#[derive(Debug, Clone, Default)]
pub struct BackendConfig {
    pub chunks: Vec<String>,
    pub tool_proposal_after: Option<usize>,
    pub crash_after: Option<usize>,
}

pub trait BackendPort {
    /// Bounded inspection + "load" into backend state. Must be
    /// deterministic; must not spawn processes or touch the network.
    fn load(&mut self, req: &LoadRequest) -> Result<LoadedModel, HostError>;
    /// Produces the ordered deterministic output for one generation.
    fn generate(&mut self, generation: &GenerationCtx) -> Result<Vec<MessageV1>, HostError>;
    /// Best-effort cancel of in-flight work (fake: no-op between steps).
    fn cancel(&mut self) {}
    /// Releases backend state for the loaded model.
    fn unload(&mut self) -> Result<(), HostError>;
}

#[derive(Debug, Clone)]
pub struct LoadedModel {
    pub model_identity: String,
    pub load_id: [u8; 16],
}

pub struct GenerationCtx {
    pub generation_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub stream_id: [u8; 16],
    /// Host-rendered prompt text for real backends (fake ignores it).
    pub prompt: String,
    pub artifact_path_hint: Option<PathBuf>,
}
