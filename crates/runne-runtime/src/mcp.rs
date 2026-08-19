//! Fail-closed runtime activation for evidence-bound MCP integration.

use runne_mcp::McpSdkIntegrationProfileRef;

/// MCP production activation rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpActivationError {
    /// No trusted ADR-0019 profile was supplied.
    SdkProfileUnavailable,
    /// Local containment or remote broker authority is unavailable.
    ContainmentUnavailable,
    /// Request belongs to a stale runtime generation.
    StaleGeneration,
}

/// Production MCP activation candidate.
pub struct McpActivationRequest {
    _profile: Option<McpSdkIntegrationProfileRef>,
    _generation: u64,
    _containment_available: bool,
}

impl McpActivationRequest {
    /// Captures a production activation candidate without granting authority.
    pub const fn production(
        profile: Option<McpSdkIntegrationProfileRef>,
        generation: u64,
        containment_available: bool,
    ) -> Self {
        Self {
            _profile: profile,
            _generation: generation,
            _containment_available: containment_available,
        }
    }

    /// Activates only an accepted exact profile in the current generation.
    pub fn activate(
        self,
        _current_generation: u64,
    ) -> Result<McpRuntimeActivation, McpActivationError> {
        Err(McpActivationError::SdkProfileUnavailable)
    }
}

/// Opaque runtime-owned active MCP profile binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRuntimeActivation {
    generation: u64,
    profile_digest: [u8; 32],
}

impl McpRuntimeActivation {
    /// Exact active runtime generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Accepted SDK integration evidence digest.
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }
}
