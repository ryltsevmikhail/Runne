use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::QuotaModelError;

const MAX_PROVIDER_ID_BYTES: usize = 128;

/// Provider endpoint used only for quota metadata; no credential is stored.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QuotaProvider {
    /// Z.ai global Coding Plan.
    ZaiGlobal,
    /// Z.ai mainland China Coding Plan endpoint.
    ZaiChina,
    /// QwenCloud individual Token Plan.
    QwenTokenPlanIndividual,
    /// Kimi for Coding managed usage endpoint.
    KimiCoding,
    /// MiniMax token-plan balance endpoint.
    MiniMax,
    /// MiniMax China token-plan balance endpoint.
    MiniMaxChina,
}

/// Identity binding for a quota observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuotaIdentity {
    provider_id: String,
    credential_version: u64,
}

impl QuotaIdentity {
    /// Constructs a bounded non-secret provider/version binding.
    pub fn new(
        provider_id: impl Into<String>,
        credential_version: u64,
    ) -> Result<Self, QuotaModelError> {
        let provider_id = provider_id.into();
        if provider_id.is_empty()
            || provider_id.len() > MAX_PROVIDER_ID_BYTES
            || !provider_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(QuotaModelError::InvalidIdentity);
        }
        Ok(Self {
            provider_id,
            credential_version,
        })
    }
    /// Returns the stable provider identifier.
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    /// Returns the secure-store credential version.
    pub const fn credential_version(&self) -> u64 {
        self.credential_version
    }
}

/// Authorization header encoding required by a quota endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QuotaAuthHeaderKind {
    /// Send the raw token as `Authorization`; do not prepend `Bearer`.
    RawAuthorization,
    /// Send `Bearer <token>` as `Authorization`.
    BearerAuthorization,
}

/// Quota endpoint scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QuotaEndpointScope {
    /// Provider API endpoint is available.
    ProviderApi,
    /// The provider exposes the remaining quota through its console.
    ConsoleRequired,
}

/// Non-secret descriptor for a future quota request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuotaRequestDescriptor {
    provider: QuotaProvider,
    endpoint: Option<&'static str>,
    auth_header: QuotaAuthHeaderKind,
    scope: QuotaEndpointScope,
}

impl QuotaRequestDescriptor {
    /// Z.ai global internal quota endpoint.
    pub const fn zai_global() -> Self {
        Self {
            provider: QuotaProvider::ZaiGlobal,
            endpoint: Some("https://api.z.ai/api/monitor/usage/quota/limit"),
            auth_header: QuotaAuthHeaderKind::RawAuthorization,
            scope: QuotaEndpointScope::ProviderApi,
        }
    }
    /// Z.ai China internal quota endpoint.
    pub const fn zai_china() -> Self {
        Self {
            provider: QuotaProvider::ZaiChina,
            endpoint: Some("https://open.bigmodel.cn/api/monitor/usage/quota/limit"),
            auth_header: QuotaAuthHeaderKind::RawAuthorization,
            scope: QuotaEndpointScope::ProviderApi,
        }
    }
    /// QwenCloud Token Plan metadata; no public REST quota endpoint is claimed.
    pub const fn qwen_token_plan_individual() -> Self {
        Self {
            provider: QuotaProvider::QwenTokenPlanIndividual,
            endpoint: None,
            auth_header: QuotaAuthHeaderKind::RawAuthorization,
            scope: QuotaEndpointScope::ConsoleRequired,
        }
    }
    /// Kimi managed usage endpoint.
    pub const fn kimi_coding() -> Self {
        Self {
            provider: QuotaProvider::KimiCoding,
            endpoint: Some("https://api.kimi.com/coding/v1/usages"),
            auth_header: QuotaAuthHeaderKind::BearerAuthorization,
            scope: QuotaEndpointScope::ProviderApi,
        }
    }
    /// MiniMax global token-plan endpoint.
    pub const fn minimax() -> Self {
        Self {
            provider: QuotaProvider::MiniMax,
            endpoint: Some("https://www.minimax.io/v1/token_plan/remains"),
            auth_header: QuotaAuthHeaderKind::BearerAuthorization,
            scope: QuotaEndpointScope::ProviderApi,
        }
    }
    /// MiniMax China token-plan endpoint.
    pub const fn minimax_china() -> Self {
        Self {
            provider: QuotaProvider::MiniMaxChina,
            endpoint: Some("https://www.minimaxi.com/v1/token_plan/remains"),
            auth_header: QuotaAuthHeaderKind::BearerAuthorization,
            scope: QuotaEndpointScope::ProviderApi,
        }
    }
    /// Returns the provider kind.
    pub fn provider(&self) -> QuotaProvider {
        self.provider.clone()
    }
    /// Returns the fixed endpoint, if one is available.
    pub const fn endpoint(&self) -> Option<&'static str> {
        self.endpoint
    }
    /// Returns the header encoding.
    pub const fn auth_header(&self) -> QuotaAuthHeaderKind {
        self.auth_header
    }
    /// Returns whether a provider API request is available.
    pub const fn scope(&self) -> QuotaEndpointScope {
        self.scope
    }

    /// Computes the non-secret binding for one exact quota operation.
    ///
    /// The caller must bind this digest into the store-issued verification
    /// capability; a provider/version check alone is insufficient because the
    /// endpoint, auth scheme and optional model affect the operation.
    #[must_use]
    pub fn binding_digest(&self, credential_version: u64, model_name: Option<&str>) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"RUNNE_QUOTA_REFRESH_V1\0");
        hasher.update([self.provider.tag()]);
        hasher.update(self.endpoint.unwrap_or_default().as_bytes());
        hasher.update([match self.auth_header {
            QuotaAuthHeaderKind::RawAuthorization => 0,
            QuotaAuthHeaderKind::BearerAuthorization => 1,
        }]);
        hasher.update([match self.scope {
            QuotaEndpointScope::ProviderApi => 0,
            QuotaEndpointScope::ConsoleRequired => 1,
        }]);
        hasher.update(credential_version.to_be_bytes());
        if let Some(model) = model_name {
            hasher.update([1]);
            hasher.update(u64::try_from(model.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(model.as_bytes());
        } else {
            hasher.update([0]);
            hasher.update(0_u64.to_be_bytes());
        }
        hasher.finalize().into()
    }
}

impl QuotaProvider {
    const fn tag(&self) -> u8 {
        match self {
            Self::ZaiGlobal => 1,
            Self::ZaiChina => 2,
            Self::QwenTokenPlanIndividual => 3,
            Self::KimiCoding => 4,
            Self::MiniMax => 5,
            Self::MiniMaxChina => 6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::QuotaRequestDescriptor;

    #[test]
    fn quota_binding_changes_for_each_operation_input() {
        let descriptor = QuotaRequestDescriptor::kimi_coding();
        let base = descriptor.binding_digest(7, None);
        assert_ne!(base, descriptor.binding_digest(8, None));
        assert_ne!(base, descriptor.binding_digest(7, Some("kimi-k2")));
        assert_ne!(
            base,
            QuotaRequestDescriptor::zai_global().binding_digest(7, None)
        );
    }
}
