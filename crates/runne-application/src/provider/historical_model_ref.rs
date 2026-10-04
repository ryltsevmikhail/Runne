use runne_provider::{ModelRef, ProviderId};

/// Exact persisted provider profile identity used to resolve a historical model.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoricalProviderProfileIdentity {
    provider_id: ProviderId,
    profile_id: String,
    profile_digest: [u8; 32],
}

impl std::fmt::Debug for HistoricalProviderProfileIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoricalProviderProfileIdentity")
            .field("provider_id", &self.provider_id)
            .field("profile_id", &self.profile_id)
            .field("profile_digest", &"[redacted]")
            .finish()
    }
}

impl HistoricalProviderProfileIdentity {
    /// Constructs an exact, bounded identity from durable admission metadata.
    pub fn new(
        provider_id: ProviderId,
        profile_id: String,
        profile_digest: [u8; 32],
    ) -> Result<Self, HistoricalProviderModelError> {
        if profile_id.is_empty()
            || profile_id.len() > 128
            || !profile_id.bytes().all(|byte| byte.is_ascii_graphic())
            || profile_digest.iter().all(|byte| *byte == 0)
        {
            return Err(HistoricalProviderModelError::InvalidIdentity);
        }
        Ok(Self {
            provider_id,
            profile_id,
            profile_digest,
        })
    }

    /// Provider realm owner from the original provider admission.
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Exact profile identifier from the original admission.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Exact immutable profile digest from the original admission.
    pub fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }
}

/// Closed failure returned when a historical profile cannot prove one model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalProviderModelError {
    /// The profile identity is malformed or outside its bound.
    InvalidIdentity,
    /// The exact historical profile is no longer available.
    ProfileUnavailable,
    /// The exact profile does not bind one unique model and revision.
    ModelAmbiguous,
}

/// Resolves only the one immutable model pinned by an exact historical profile.
///
/// Implementations must key by all three identity fields and must not consult a
/// current default, alias, credential, request JSON, or caller-supplied model.
pub trait HistoricalProviderModelResolver: Send + Sync {
    /// Returns the unique model pinned by this exact historic profile identity.
    fn resolve_exact(
        &self,
        identity: &HistoricalProviderProfileIdentity,
    ) -> Result<ModelRef, HistoricalProviderModelError>;
}
