/// Production SDK composition is structurally disabled until an accepted
/// ADR-0019 implementation is compiled into the repository.
pub const PRODUCTION_MCP_SDK_ENABLED: bool = false;

use crate::InvalidMcpIdentity;

/// Stable SDK integration profile identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSdkIntegrationProfileId(String);

impl McpSdkIntegrationProfileId {
    /// Creates a bounded printable profile identity.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidMcpIdentity> {
        let value = value.into();
        if value.is_empty() {
            return Err(InvalidMcpIdentity::Empty);
        }
        if value.len() > 128 {
            return Err(InvalidMcpIdentity::TooLong);
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(InvalidMcpIdentity::InvalidCharacter);
        }
        Ok(Self(value))
    }
    /// Returns profile text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact evidence required by ADR-0019.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSdkIntegrationEvidence {
    /// Exact non-prerelease SDK version.
    pub sdk_version: String,
    /// Exact source/checksum digest.
    pub source_checksum: [u8; 32],
    /// Feature and dependency graph digest.
    pub dependency_digest: [u8; 32],
    /// Exact stable protocol version.
    pub protocol_version: String,
    /// Complete passing conformance inventory digest.
    pub conformance_digest: [u8; 32],
    /// No-hidden-spawn/redaction/cancellation evidence.
    pub behavior_evidence_digest: Option<[u8; 32]>,
    /// MSRV and platform matrix evidence.
    pub platform_evidence_digest: Option<[u8; 32]>,
    /// Fresh advisory and license evidence.
    pub supply_chain_evidence_digest: Option<[u8; 32]>,
}

/// Exact evidence-bound production profile reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSdkIntegrationProfileRef {
    profile_id: McpSdkIntegrationProfileId,
    revision: u64,
    digest: [u8; 32],
}

impl McpSdkIntegrationProfileRef {
    /// Creates authority only when every ADR-0019 production gate is present.
    pub fn production(
        _profile_id: McpSdkIntegrationProfileId,
        _revision: u64,
        _evidence: McpSdkIntegrationEvidence,
    ) -> Result<Self, SdkProfileUnavailable> {
        Err(SdkProfileUnavailable)
    }
    /// Profile identity.
    pub const fn profile_id(&self) -> &McpSdkIntegrationProfileId {
        &self.profile_id
    }
    /// Monotonic revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Exact evidence digest.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Production SDK profile is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdkProfileUnavailable;
