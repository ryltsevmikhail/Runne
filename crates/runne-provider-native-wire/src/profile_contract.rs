use super::{AnthropicMessagesProfile, GeminiProfile, NativeWireProfile, pricing};
use runne_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
    TextProviderProfile,
};

macro_rules! impl_profile_contract {
    ($profile:ty) => {
        impl TextProviderProfile for $profile {
            fn profile_id(&self) -> &str {
                self.profile_id()
            }
            fn profile_digest(&self) -> [u8; 32] {
                self.profile_digest()
            }
            fn pricing_revision_digest(&self) -> [u8; 32] {
                self.pricing_revision_digest()
            }
            fn currency(&self) -> &str {
                pricing::currency(self.accounting())
            }
            fn max_input_bytes(&self) -> usize {
                self.limits().max_input_bytes()
            }
            fn max_input_entries(&self) -> usize {
                self.limits().max_input_entries()
            }
            fn max_input_entry_bytes(&self) -> usize {
                self.limits().max_input_entry_bytes()
            }
            fn max_output_tokens(&self) -> u32 {
                self.limits().max_output_tokens()
            }
            fn max_request_bytes(&self) -> usize {
                self.limits().max_request_bytes()
            }
            fn price_usage_micros(
                &self,
                usage: ProviderUsage,
            ) -> Result<u64, ProviderTerminalPricingError> {
                pricing::price_usage(self.accounting(), usage)
            }

            fn call_binding_extension(&self) -> serde_json::Value {
                self.binding_extension()
            }
        }

        impl ProviderTerminalPricing for $profile {
            fn price_terminal_usage(
                &self,
                pricing_digest: &[u8; 32],
                profile_digest: &[u8; 32],
                _effect_started_at: i64,
                usage: ProviderUsage,
            ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
                if pricing_digest != &self.pricing_revision_digest()
                    || profile_digest != &self.profile_digest()
                {
                    return Err(ProviderTerminalPricingError::Unavailable);
                }
                pricing::price_terminal(self.accounting(), usage)
            }
        }
    };
}

impl_profile_contract!(AnthropicMessagesProfile);
impl_profile_contract!(GeminiProfile);

impl TextProviderProfile for NativeWireProfile {
    fn profile_id(&self) -> &str {
        match self {
            Self::Anthropic(profile) => profile.profile_id(),
            Self::Gemini(profile) => profile.profile_id(),
        }
    }
    fn profile_digest(&self) -> [u8; 32] {
        Self::profile_digest(self)
    }
    fn pricing_revision_digest(&self) -> [u8; 32] {
        match self {
            Self::Anthropic(profile) => profile.pricing_revision_digest(),
            Self::Gemini(profile) => profile.pricing_revision_digest(),
        }
    }
    fn currency(&self) -> &'static str {
        pricing::currency(self.accounting())
    }
    fn max_input_bytes(&self) -> usize {
        self.limits().max_input_bytes()
    }
    fn max_input_entries(&self) -> usize {
        self.limits().max_input_entries()
    }
    fn max_input_entry_bytes(&self) -> usize {
        self.limits().max_input_entry_bytes()
    }
    fn max_output_tokens(&self) -> u32 {
        self.limits().max_output_tokens()
    }
    fn max_request_bytes(&self) -> usize {
        self.limits().max_request_bytes()
    }
    fn price_usage_micros(
        &self,
        usage: ProviderUsage,
    ) -> Result<u64, ProviderTerminalPricingError> {
        pricing::price_usage(self.accounting(), usage)
    }

    fn call_binding_extension(&self) -> serde_json::Value {
        match self {
            Self::Anthropic(profile) => profile.binding_extension(),
            Self::Gemini(profile) => profile.binding_extension(),
        }
    }
}

impl ProviderTerminalPricing for NativeWireProfile {
    fn price_terminal_usage(
        &self,
        pricing_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        _effect_started_at: i64,
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        if pricing_digest != &self.pricing_revision_digest()
            || profile_digest != &self.profile_digest()
        {
            return Err(ProviderTerminalPricingError::Unavailable);
        }
        pricing::price_terminal(self.accounting(), usage)
    }
}
