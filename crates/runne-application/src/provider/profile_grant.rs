use runne_provider::ProviderId;

use super::ProviderAdmissionError;

/// Exact immutable secondary profile and its independent admission budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSecondaryProfileGrantSpec {
    provider_id: String,
    profile_id: String,
    credential_realm: String,
    profile_digest: [u8; 32],
    pricing_revision_digest: [u8; 32],
    token_budget_limit: u64,
    cost_budget_limit_micros: u64,
}

impl ProviderSecondaryProfileGrantSpec {
    /// Creates a bounded grant specification; it carries no authority by itself.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: &ProviderId,
        profile_id: &str,
        credential_realm: &str,
        profile_digest: [u8; 32],
        pricing_revision_digest: [u8; 32],
        token_budget_limit: u64,
        cost_budget_limit_micros: u64,
    ) -> Result<Self, ProviderAdmissionError> {
        if !valid_label(provider_id.as_str(), 128)
            || !valid_label(profile_id, 128)
            || !valid_label(credential_realm, 128)
            || provider_id.as_str() != credential_realm
            || profile_digest == [0; 32]
            || pricing_revision_digest == [0; 32]
            || token_budget_limit == 0
            || cost_budget_limit_micros == 0
            || token_budget_limit > i64::MAX as u64
            || cost_budget_limit_micros > i64::MAX as u64
        {
            return Err(ProviderAdmissionError::InvalidSemanticContext);
        }
        Ok(Self {
            provider_id: provider_id.as_str().to_owned(),
            profile_id: profile_id.to_owned(),
            credential_realm: credential_realm.to_owned(),
            profile_digest,
            pricing_revision_digest,
            token_budget_limit,
            cost_budget_limit_micros,
        })
    }

    /// Canonical selected provider route.
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    /// Immutable selected profile identifier.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    /// Exact secure-store credential realm.
    pub fn credential_realm(&self) -> &str {
        &self.credential_realm
    }
    /// Immutable profile digest.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }
    /// Immutable pricing digest.
    pub const fn pricing_revision_digest(&self) -> [u8; 32] {
        self.pricing_revision_digest
    }
    /// Independent token limit.
    pub const fn token_budget_limit(&self) -> u64 {
        self.token_budget_limit
    }
    /// Independent cost limit in micros.
    pub const fn cost_budget_limit_micros(&self) -> u64 {
        self.cost_budget_limit_micros
    }
}

fn valid_label(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_limits_and_credential_realm_alias_mismatch() {
        let provider = ProviderId::new("openai-background").unwrap();
        assert!(
            ProviderSecondaryProfileGrantSpec::new(
                &provider, "text/1", "openai", [1; 32], [2; 32], 10, 20
            )
            .is_err()
        );
        assert!(
            ProviderSecondaryProfileGrantSpec::new(
                &provider,
                "text/1",
                "openai-background",
                [1; 32],
                [2; 32],
                0,
                20
            )
            .is_err()
        );
    }
}
