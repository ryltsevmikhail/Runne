use crate::profile_components::{ProfileError, valid_component};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

/// Provider family with an exact Responses endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponsesProvider {
    /// OpenAI Codex subscription backend.
    OpenAiCodex,
    /// GitHub Copilot Responses-compatible endpoint.
    GithubCopilot,
    /// Azure OpenAI Responses deployment.
    AzureOpenAi,
    /// xAI Responses endpoint.
    Xai,
}

/// Accounting contract for a Responses profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponsesAccounting {
    /// Subscription usage is metered by the provider quota authority.
    SubscriptionQuotaExternallyMetered,
    /// PAYG rates pinned by an external accounting contract.
    Payg {
        /// Input rate in micro-USD per million tokens.
        input_micros_per_million: u64,
        /// Output rate in micro-USD per million tokens.
        output_micros_per_million: u64,
        /// Cached input rate in micro-USD per million tokens.
        cached_input_micros_per_million: u64,
    },
    /// Provider billing is external and no trusted price is available.
    ExternallyBilledUnpriced,
}

/// Immutable profile used by both request rendering and stream validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsesProfile {
    pub(crate) provider: ResponsesProvider,
    pub(crate) provider_id: Cow<'static, str>,
    pub(crate) profile_id: String,
    pub(crate) model: String,
    pub(crate) model_revision: String,
    pub(crate) endpoint: Cow<'static, str>,
    pub(crate) deployment: Option<String>,
    pub(crate) aliases: Vec<String>,
    pub(crate) binding_extension: Value,
    pub(crate) pricing_digest: [u8; 32],
    pub(crate) accounting: ResponsesAccounting,
    pub(crate) max_input_entries: usize,
    pub(crate) max_input_entry_bytes: usize,
    pub(crate) max_input_bytes: usize,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_output_tokens: u32,
}
impl ResponsesProfile {
    /// Creates a fixed profile; aliases are explicit response model aliases.
    pub fn new(provider: ResponsesProvider, model: impl Into<String>) -> Self {
        let (provider_id, endpoint) = match provider {
            ResponsesProvider::OpenAiCodex => (
                "openai-codex",
                "https://chatgpt.com/backend-api/codex/responses",
            ),
            ResponsesProvider::GithubCopilot => (
                "github-copilot",
                "https://api.individual.githubcopilot.com/responses",
            ),
            ResponsesProvider::AzureOpenAi => (
                "azure-openai-responses",
                "https://{resource}.openai.azure.com/openai/v1/responses",
            ),
            ResponsesProvider::Xai => ("xai", "https://api.x.ai/v1/responses"),
        };
        let model = model.into();
        let profile_id = format!("gocode-responses/{provider_id}/{model}/1");
        Self {
            provider,
            provider_id: Cow::Borrowed(provider_id),
            profile_id,
            model,
            model_revision: String::new(),
            endpoint: Cow::Borrowed(endpoint),
            deployment: None,
            aliases: Vec::new(),
            binding_extension: Value::Null,
            pricing_digest: [0; 32],
            accounting: ResponsesAccounting::ExternallyBilledUnpriced,
            max_input_entries: 64,
            max_input_entry_bytes: 131_072,
            max_input_bytes: 1_048_576,
            max_request_bytes: 2 * 1_048_576,
            max_output_tokens: 16_384,
        }
    }

    /// Creates Azure profile with validated resource and deployment names.
    pub fn azure(
        resource: &str,
        deployment: &str,
        model: impl Into<String>,
    ) -> Result<Self, ProfileError> {
        if !valid_component(resource) || !valid_component(deployment) {
            return Err(ProfileError::InvalidComponent);
        }
        let mut profile = Self::new(ResponsesProvider::AzureOpenAi, model);
        profile.endpoint = Cow::Owned(format!(
            "https://{resource}.openai.azure.com/openai/v1/responses"
        ));
        profile.deployment = Some(deployment.to_owned());
        Ok(profile)
    }
    /// Adds one permitted response model alias.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Result<Self, ProfileError> {
        let alias = alias.into();
        if !Self::valid_alias(&self.aliases, &alias) {
            return Err(ProfileError::InvalidComponent);
        }
        self.aliases.push(alias);
        Ok(self)
    }
    /// Binds the immutable model revision required by prepared calls.
    #[must_use]
    pub fn with_model_revision(mut self, revision: impl Into<String>) -> Self {
        self.model_revision = revision.into();
        self
    }
    /// Binds the canonical provider extension for this profile.
    #[must_use]
    pub fn with_binding_extension(mut self, extension: Value) -> Self {
        self.binding_extension = extension;
        self
    }
    /// Binds the accounting contract digest supplied by the authority layer.
    #[must_use]
    pub const fn with_pricing_revision_digest(mut self, digest: [u8; 32]) -> Self {
        self.pricing_digest = digest;
        self
    }
    /// Binds explicit subscription or PAYG accounting semantics.
    #[must_use]
    pub const fn with_accounting(mut self, accounting: ResponsesAccounting) -> Self {
        self.accounting = accounting;
        self
    }
    /// Sets bounded text request limits for this model profile.
    #[must_use]
    pub const fn with_limits(
        mut self,
        max_input_entries: usize,
        max_input_entry_bytes: usize,
        max_input_bytes: usize,
        max_request_bytes: usize,
    ) -> Self {
        self.max_input_entries = max_input_entries;
        self.max_input_entry_bytes = max_input_entry_bytes;
        self.max_input_bytes = max_input_bytes;
        self.max_request_bytes = max_request_bytes;
        self
    }
    /// Sets the local output reservation bound. Codex does not send this as a wire field.
    #[must_use]
    pub const fn with_max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.max_output_tokens = max_output_tokens;
        self
    }
    /// Provider family.
    pub const fn provider(&self) -> ResponsesProvider {
        self.provider
    }
    /// Stable Runne provider id.
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    /// Exact immutable Runne profile id, including provider and model.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    /// Expected request and response model id.
    pub fn model(&self) -> &str {
        &self.model
    }
    /// Azure deployment sent as the request model; other providers use `model`.
    pub fn request_model(&self) -> &str {
        self.deployment.as_deref().unwrap_or(&self.model)
    }
    /// Exact model revision required by `prepare_call`.
    pub fn model_revision(&self) -> &str {
        &self.model_revision
    }
    /// Exact extension value required by `prepare_call`.
    pub const fn binding_extension(&self) -> &Value {
        &self.binding_extension
    }

    /// Accounting contract digest bound to this profile.
    pub const fn pricing_revision_digest(&self) -> [u8; 32] {
        self.pricing_digest
    }
    /// Maximum output requested by the Responses text profile.
    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }
    /// Maximum number of text turns accepted by this profile.
    pub const fn max_input_entries(&self) -> usize {
        self.max_input_entries
    }
    /// Maximum bytes in one text turn.
    pub const fn max_input_entry_bytes(&self) -> usize {
        self.max_input_entry_bytes
    }
    /// Maximum aggregate text input bytes.
    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }
    /// Maximum rendered request bytes.
    pub const fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }
    /// Accounting contract kind.
    pub const fn accounting(&self) -> ResponsesAccounting {
        self.accounting
    }
    /// Currency marker for accounting output; `XXX` means no monetary estimate.
    pub const fn currency(&self) -> &'static str {
        match self.accounting {
            ResponsesAccounting::Payg { .. } => "USD",
            ResponsesAccounting::SubscriptionQuotaExternallyMetered
            | ResponsesAccounting::ExternallyBilledUnpriced => "XXX",
        }
    }
    /// Exact endpoint template. Azure resource substitution is performed by the host.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    /// Stable digest binding provider, endpoint and model configuration.
    pub fn profile_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"runne/responses-profile/v1\0");
        for value in [
            self.provider_id.as_ref(),
            self.profile_id.as_str(),
            self.endpoint.as_ref(),
            self.model.as_str(),
            self.model_revision.as_str(),
        ] {
            Self::update_field(&mut digest, value.as_bytes());
        }
        Self::update_field(
            &mut digest,
            &serde_json::to_vec(&self.binding_extension).unwrap_or_default(),
        );
        digest.update(self.pricing_digest);
        digest.update([match self.accounting {
            ResponsesAccounting::SubscriptionQuotaExternallyMetered => 1,
            ResponsesAccounting::Payg { .. } => 2,
            ResponsesAccounting::ExternallyBilledUnpriced => 3,
        }]);
        if let ResponsesAccounting::Payg {
            input_micros_per_million,
            output_micros_per_million,
            cached_input_micros_per_million,
        } = self.accounting
        {
            digest.update(input_micros_per_million.to_be_bytes());
            digest.update(output_micros_per_million.to_be_bytes());
            digest.update(cached_input_micros_per_million.to_be_bytes());
        }
        digest.update(self.max_output_tokens.to_be_bytes());
        digest.update((self.max_input_entries as u64).to_be_bytes());
        digest.update((self.max_input_entry_bytes as u64).to_be_bytes());
        digest.update((self.max_input_bytes as u64).to_be_bytes());
        digest.update((self.max_request_bytes as u64).to_be_bytes());
        digest.update([u8::from(self.deployment.is_some())]);
        if let Some(deployment) = &self.deployment {
            Self::update_field(&mut digest, deployment.as_bytes());
        }
        digest.update((self.aliases.len() as u64).to_be_bytes());
        for alias in &self.aliases {
            Self::update_field(&mut digest, alias.as_bytes());
        }
        digest.finalize().into()
    }
    /// Checks the explicit model alias policy.
    pub fn accepts_model(&self, model: &str) -> bool {
        model == self.model || self.aliases.iter().any(|v| v == model)
    }
    pub(crate) fn aliases(&self) -> &[String] {
        &self.aliases
    }
}
#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
