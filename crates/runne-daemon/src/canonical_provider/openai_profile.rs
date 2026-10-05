use super::*;
use runne_provider::{ProviderTerminalPricing, ProviderTerminalPricingError};
use runne_provider_openai::OpenAiResponsesTextProfile;

pub(crate) struct OpenAiTextProviderProfile(OpenAiResponsesTextProfile);

impl OpenAiTextProviderProfile {
    pub(crate) const fn new(profile: OpenAiResponsesTextProfile) -> Self {
        Self(profile)
    }
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(super) fn opt_in_tool_profile(
    text_profile: &SharedTextProviderProfile,
) -> Option<Arc<SharedTextProviderProfile>> {
    #[cfg(not(all(target_os = "linux", feature = "desktop-protected")))]
    {
        let _ = text_profile;
        return None;
    }
    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    {
        let profile = OpenAiResponsesTextProfile::from_json(include_bytes!(
            "../../../../docs/profiles/openai-responses-text-v1.json"
        ))
        .ok()?;
        if text_profile.profile_id() != profile.profile_id()
            || text_profile.profile_digest() != profile.profile_digest()
        {
            return None;
        }
        let tool_profile = runne_provider_openai::OpenAiResponsesToolProfile::new(profile).ok()?;
        Some(Arc::new(SharedTextProviderProfile::new(Arc::new(
            tool_profile,
        ))))
    }
}

impl ProviderTerminalPricing for OpenAiTextProviderProfile {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        effect_started_at: i64,
        usage: ProviderUsage,
    ) -> Result<runne_provider::ProviderPricedUsage, ProviderTerminalPricingError> {
        self.0.price_terminal_usage(
            pricing_revision_digest,
            profile_digest,
            effect_started_at,
            usage,
        )
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
                0,
                usage,
            )
            .map(|priced| priced.charge_micros())
    }
}
