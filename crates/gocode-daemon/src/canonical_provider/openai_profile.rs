use super::*;
use gocode_provider::{ProviderTerminalPricing, ProviderTerminalPricingError};
use gocode_provider_openai::OpenAiResponsesTextProfile;

pub(crate) struct OpenAiTextProviderProfile(OpenAiResponsesTextProfile);

impl OpenAiTextProviderProfile {
    pub(crate) const fn new(profile: OpenAiResponsesTextProfile) -> Self {
        Self(profile)
    }
}

impl ProviderTerminalPricing for OpenAiTextProviderProfile {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        usage: ProviderUsage,
    ) -> Result<gocode_provider::ProviderPricedUsage, ProviderTerminalPricingError> {
        self.0
            .price_terminal_usage(pricing_revision_digest, profile_digest, usage)
    }
}

impl TextProviderProfile for OpenAiTextProviderProfile {
    fn profile_id(&self) -> &str {
        self.0.profile_id()
    }

    fn profile_digest(&self) -> [u8; 32] {
        self.0.profile_digest()
    }

    fn pricing_revision_digest(&self) -> [u8; 32] {
        self.0.pricing_revision_digest()
    }

    fn currency(&self) -> &str {
        self.0.currency()
    }

    fn max_input_bytes(&self) -> usize {
        self.0.max_input_bytes()
    }

    fn max_input_entries(&self) -> usize {
        self.0.max_input_entries()
    }

    fn max_input_entry_bytes(&self) -> usize {
        self.0.max_input_entry_bytes()
    }

    fn max_output_tokens(&self) -> u32 {
        self.0.max_output_tokens()
    }

    fn max_request_bytes(&self) -> usize {
        self.0.max_request_bytes()
    }

    fn price_usage_micros(
        &self,
        usage: ProviderUsage,
    ) -> Result<u64, ProviderTerminalPricingError> {
        self.0
            .price_terminal_usage(
                &self.0.pricing_revision_digest(),
                &self.0.profile_digest(),
                usage,
            )
            .map(|priced| priced.charge_micros())
    }
}
