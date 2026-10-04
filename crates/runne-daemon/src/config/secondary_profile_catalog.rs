/// Explicit owner-private opt-in for the isolated OpenAI background route.
///
/// This config contains identity and limits only. It is not an admission
/// capability, and it never changes the primary provider activation.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondaryProfileCatalogConfig {
    provider_id: String,
    profile_id: String,
    credential_realm: String,
    profile_digest: String,
    pricing_revision_digest: String,
    token_budget_limit: u64,
    cost_budget_limit_micros: u64,
}

impl SecondaryProfileCatalogConfig {
    pub(crate) fn provider_id(&self) -> &str {
        &self.provider_id
    }
    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }
    pub(crate) fn credential_realm(&self) -> &str {
        &self.credential_realm
    }
    pub(crate) fn profile_digest(&self) -> &str {
        &self.profile_digest
    }
    pub(crate) fn pricing_revision_digest(&self) -> &str {
        &self.pricing_revision_digest
    }
    pub(crate) const fn token_budget_limit(&self) -> u64 {
        self.token_budget_limit
    }
    pub(crate) const fn cost_budget_limit_micros(&self) -> u64 {
        self.cost_budget_limit_micros
    }
}
