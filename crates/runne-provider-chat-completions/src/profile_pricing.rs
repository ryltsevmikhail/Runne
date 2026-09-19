use super::{ChatCompletionsAccounting, ChatCompletionsProfile};
use runne_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
    TextProviderProfile,
};

impl ProviderTerminalPricing for ChatCompletionsProfile {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        if pricing_revision_digest != &self.pricing_digest || profile_digest != &self.profile_digest
        {
            return Err(ProviderTerminalPricingError::Unavailable);
        }
        let charge = self.price_usage_micros(usage)?;
        ProviderPricedUsage::new(charge, self.currency().to_owned())
    }
}

impl TextProviderProfile for ChatCompletionsProfile {
    fn profile_id(&self) -> &str {
        self.profile_id.as_ref()
    }
    fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }
    fn pricing_revision_digest(&self) -> [u8; 32] {
        self.pricing_digest
    }
    fn currency(&self) -> &str {
        self.currency()
    }
    fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }
    fn max_input_entries(&self) -> usize {
        self.max_input_entries
    }
    fn max_input_entry_bytes(&self) -> usize {
        self.max_input_entry_bytes
    }
    fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }
    fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }
    fn price_usage_micros(
        &self,
        usage: ProviderUsage,
    ) -> Result<u64, ProviderTerminalPricingError> {
        match self.accounting {
            ChatCompletionsAccounting::SubscriptionQuotaExternallyMetered => Ok(0),
            ChatCompletionsAccounting::ExternallyBilledUnpriced => {
                Err(ProviderTerminalPricingError::Unavailable)
            }
            ChatCompletionsAccounting::Payg {
                input_micros_per_million,
                output_micros_per_million,
                cached_input_micros_per_million,
            } => {
                let uncached = usage
                    .input_tokens()
                    .checked_sub(usage.cached_input_tokens())
                    .ok_or(ProviderTerminalPricingError::InvalidQuote)?;
                let input = prorated_micros(uncached, input_micros_per_million)?;
                let output = prorated_micros(usage.output_tokens(), output_micros_per_million)?;
                let cached =
                    prorated_micros(usage.cached_input_tokens(), cached_input_micros_per_million)?;
                input
                    .checked_add(output)
                    .and_then(|total| total.checked_add(cached))
                    .ok_or(ProviderTerminalPricingError::InvalidQuote)
            }
        }
    }
}

fn prorated_micros(
    tokens: u64,
    micros_per_million: u64,
) -> Result<u64, ProviderTerminalPricingError> {
    if tokens == 0 || micros_per_million == 0 {
        return Ok(0);
    }
    let numerator = tokens
        .checked_mul(micros_per_million)
        .ok_or(ProviderTerminalPricingError::InvalidQuote)?;
    numerator
        .checked_add(1_000_000 - 1)
        .map(|value| value / 1_000_000)
        .ok_or(ProviderTerminalPricingError::InvalidQuote)
}
