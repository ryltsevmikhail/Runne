use super::*;
use runne_provider::{ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError};

pub(crate) struct SharedTextProviderProfile {
    inner: Arc<dyn TextProviderProfile>,
}

impl SharedTextProviderProfile {
    pub(crate) const fn new(inner: Arc<dyn TextProviderProfile>) -> Self {
        Self { inner }
    }
}

impl ProviderTerminalPricing for SharedTextProviderProfile {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        effect_started_at: i64,
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        self.inner.price_terminal_usage(
            pricing_revision_digest,
            profile_digest,
            effect_started_at,
            usage,
        )
    }
}

impl TextProviderProfile for SharedTextProviderProfile {
    fn profile_id(&self) -> &str {
        self.inner.profile_id()
    }

    fn profile_digest(&self) -> [u8; 32] {
        self.inner.profile_digest()
    }

    fn pricing_revision_digest(&self) -> [u8; 32] {
        self.inner.pricing_revision_digest()
    }

    fn currency(&self) -> &str {
        self.inner.currency()
    }

    fn max_input_bytes(&self) -> usize {
        self.inner.max_input_bytes()
    }

    fn max_input_entries(&self) -> usize {
        self.inner.max_input_entries()
    }

    fn max_input_entry_bytes(&self) -> usize {
        self.inner.max_input_entry_bytes()
    }

    fn max_output_tokens(&self) -> u32 {
        self.inner.max_output_tokens()
    }

    fn max_request_bytes(&self) -> usize {
        self.inner.max_request_bytes()
    }

    fn price_usage_micros(
        &self,
        usage: ProviderUsage,
    ) -> Result<u64, ProviderTerminalPricingError> {
        self.inner.price_usage_micros(usage)
    }
}
