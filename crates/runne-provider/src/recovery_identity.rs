use crate::{ProviderId, ProviderRecoveryError};

/// Exact immutable provider admission identity, excluding live authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRecoveryAttemptIdentity {
    provider_id: ProviderId,
    credential_realm: ProviderId,
    profile_id: String,
    profile_digest: [u8; 32],
    semantic_digest: [u8; 32],
    prepared_digest: [u8; 32],
    pricing_digest: [u8; 32],
    request_digest: [u8; 32],
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    runtime_generation: u64,
    fencing_token: u64,
}

impl ProviderRecoveryAttemptIdentity {
    /// Validates the historical provider/profile/request and launch binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: ProviderId,
        credential_realm: ProviderId,
        profile_id: impl Into<String>,
        profile_digest: [u8; 32],
        semantic_digest: [u8; 32],
        prepared_digest: [u8; 32],
        pricing_digest: [u8; 32],
        request_digest: [u8; 32],
        runtime_authority_id: [u8; 16],
        database_generation: u64,
        runtime_generation: u64,
        fencing_token: u64,
    ) -> Result<Self, ProviderRecoveryError> {
        let profile_id = profile_id.into();
        if profile_id.is_empty()
            || profile_id.len() > 128
            || !profile_id.bytes().all(|byte| byte.is_ascii_graphic())
            || profile_digest == [0; 32]
            || semantic_digest == [0; 32]
            || prepared_digest == [0; 32]
            || pricing_digest == [0; 32]
            || request_digest == [0; 32]
            || runtime_authority_id == [0; 16]
            || database_generation == 0
            || runtime_generation == 0
            || fencing_token == 0
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        Ok(Self {
            provider_id,
            credential_realm,
            profile_id,
            profile_digest,
            semantic_digest,
            prepared_digest,
            pricing_digest,
            request_digest,
            runtime_authority_id,
            database_generation,
            runtime_generation,
            fencing_token,
        })
    }

    /// Provider admitted for this exact attempt.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
    /// Independent native credential account for this attempt.
    pub const fn credential_realm(&self) -> &ProviderId {
        &self.credential_realm
    }
    /// Immutable versioned profile identity.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    /// Immutable profile digest.
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }
    /// Canonical semantic request digest.
    pub const fn semantic_digest(&self) -> &[u8; 32] {
        &self.semantic_digest
    }
    /// Prepared request digest.
    pub const fn prepared_digest(&self) -> &[u8; 32] {
        &self.prepared_digest
    }
    /// Immutable pricing revision digest.
    pub const fn pricing_digest(&self) -> &[u8; 32] {
        &self.pricing_digest
    }
    /// Digest of the exact rendered provider request.
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    /// Historical runtime authority identity.
    pub const fn runtime_authority_id(&self) -> &[u8; 16] {
        &self.runtime_authority_id
    }
    /// Historical database generation.
    pub const fn database_generation(&self) -> u64 {
        self.database_generation
    }
    /// Historical runtime generation.
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }
    /// Historical fencing token.
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }
}
