//! Grant DTOs and roles. Raw artifact paths are structurally impossible
//! here: grants carry content digests and opaque descriptors only, and
//! `Debug` impls never render bytes, handles or locations.

use runne_engine_broker::broker::artifact::GrantRole as SecRole;

/// Recipient role for a grant (INTERFACES §ModelArtifactBrokerPort):
/// host inspection (metadata read) vs backend worker load (weights).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRole {
    HostInspection,
    BackendWorkerLoad { worker_generation: u64 },
}

impl GrantRole {
    pub fn to_security(self) -> SecRole {
        match self {
            Self::HostInspection => SecRole::HostInspection,
            Self::BackendWorkerLoad { worker_generation } => {
                SecRole::BackendWorkerLoad { worker_generation }
            }
        }
    }
}

/// Request for a one-time load grant. No source paths: the artifact is
/// addressed by its manifest-bound content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactGrantRequest {
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub byte_len: u64,
    pub role: GrantRole,
    pub host_generation: u64,
    pub load_id: [u8; 16],
    pub session_id: [u8; 16],
    /// Expiry as unix seconds (bounded; engine policy caps the window).
    pub ttl_secs: u64,
}

/// Sanitized grant issued to the adapter. `Debug` shows identity metadata
/// only — never bytes, descriptors or locations.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactGrant {
    pub grant_id: u64,
    pub artifact_digest: String,
    pub byte_len: u64,
    pub role: GrantRole,
    pub host_generation: u64,
    pub load_id: [u8; 16],
    pub expires_at: u64,
}

impl std::fmt::Debug for ArtifactGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtifactGrant")
            .field("grant_id", &self.grant_id)
            .field("artifact_digest", &self.artifact_digest)
            .field("byte_len", &self.byte_len)
            .field("role", &self.role)
            .field("host_generation", &self.host_generation)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
