use crate::{ResponsesAccounting, ResponsesProfile};
use runne_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
    TextProviderProfile,
};

impl ProviderTerminalPricing for ResponsesProfile {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        _effect_started_at: i64,
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        if pricing_revision_digest != &self.pricing_revision_digest()
            || profile_digest != &self.profile_digest()
        {
            return Err(ProviderTerminalPricingError::Unavailable);
        }
        let (charge, currency) = match self.accounting() {
            ResponsesAccounting::SubscriptionQuotaExternallyMetered => (0, "XXX"),
            ResponsesAccounting::ExternallyBilledUnpriced => {
                return Err(ProviderTerminalPricingError::Unavailable);
            }
            ResponsesAccounting::Payg {
                input_micros_per_million,
                output_micros_per_million,
                cached_input_micros_per_million,
            } => {
                if input_micros_per_million == 0 || output_micros_per_million == 0 {
                    return Err(ProviderTerminalPricingError::InvalidQuote);
                }
                let uncached = usage
                    .input_tokens()
                    .checked_sub(usage.cached_input_tokens())
                    .ok_or(ProviderTerminalPricingError::InvalidQuote)?;
                let input = ceil_micros(uncached, input_micros_per_million)?;
                let cached =
                    ceil_micros(usage.cached_input_tokens(), cached_input_micros_per_million)?;
                let output = ceil_micros(usage.output_tokens(), output_micros_per_million)?;
                (
                    input
                        .checked_add(cached)
                        .and_then(|value| value.checked_add(output))
                        .ok_or(ProviderTerminalPricingError::InvalidQuote)?,
                    "USD",
                )
            }
        };
        ProviderPricedUsage::new(charge, currency.to_owned())
            .map_err(|_| ProviderTerminalPricingError::InvalidQuote)
    }
}

impl TextProviderProfile for ResponsesProfile {
    fn profile_id(&self) -> &str {
        self.profile_id()
    }
    fn profile_digest(&self) -> [u8; 32] {
        Self::profile_digest(self)
    }
    fn pricing_revision_digest(&self) -> [u8; 32] {
        Self::pricing_revision_digest(self)
    }
    fn currency(&self) -> &str {
        Self::currency(self)
    }
    fn max_input_bytes(&self) -> usize {
        Self::max_input_bytes(self)
    }
    fn max_input_entries(&self) -> usize {
        Self::max_input_entries(self)
    }
    fn max_input_entry_bytes(&self) -> usize {
        Self::max_input_entry_bytes(self)
    }
    fn max_output_tokens(&self) -> u32 {
        Self::max_output_tokens(self)
    }
    fn max_request_bytes(&self) -> usize {
        Self::max_request_bytes(self)
    }
    fn price_usage_micros(
        &self,
        usage: ProviderUsage,
    ) -> Result<u64, ProviderTerminalPricingError> {
        self.price_terminal_usage(
            &self.pricing_revision_digest(),
            &self.profile_digest(),
            0,
            usage,
        )
        .map(|priced| priced.charge_micros())
    }

    fn call_binding_extension(&self) -> serde_json::Value {
        self.effective_binding_extension()
    }
}

fn ceil_micros(tokens: u64, rate_per_million: u64) -> Result<u64, ProviderTerminalPricingError> {
    tokens
        .checked_mul(rate_per_million)
        .and_then(|value| value.checked_add(999_999))
        .map(|value| value / 1_000_000)
        .ok_or(ProviderTerminalPricingError::InvalidQuote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResponsesProvider;

    fn usage() -> ProviderUsage {
        ProviderUsage::new(1_000_001, 2, 1, 0).unwrap()
    }

    #[test]
    fn subscription_is_explicit_xxx_and_unpriced_fails_closed() {
        let subscription = ResponsesProfile::new(ResponsesProvider::OpenAiCodex, "gpt-5.2")
            .with_model_revision("r")
            .with_pricing_revision_digest([1; 32])
            .with_accounting(ResponsesAccounting::SubscriptionQuotaExternallyMetered);
        let priced = subscription
            .price_terminal_usage(&[1; 32], &subscription.profile_digest(), 0, usage())
            .unwrap();
        assert_eq!((priced.charge_micros(), priced.currency()), (0, "XXX"));
        let unpriced = ResponsesProfile::new(ResponsesProvider::Xai, "grok")
            .with_model_revision("r")
            .with_pricing_revision_digest([1; 32]);
        assert_eq!(
            unpriced.price_usage_micros(usage()),
            Err(ProviderTerminalPricingError::Unavailable)
        );
    }

    #[test]
    fn payg_rounds_each_dimension_up_and_binds_digests() {
        let profile = ResponsesProfile::new(ResponsesProvider::Xai, "grok")
            .with_model_revision("r")
            .with_pricing_revision_digest([2; 32])
            .with_accounting(ResponsesAccounting::Payg {
                input_micros_per_million: 10,
                output_micros_per_million: 20,
                cached_input_micros_per_million: 1,
            });
        let priced = profile.price_usage_micros(usage()).unwrap();
        assert_eq!(priced, 12);
        assert_eq!(
            profile.price_terminal_usage(&[3; 32], &profile.profile_digest(), 0, usage()),
            Err(ProviderTerminalPricingError::Unavailable)
        );
    }
}
