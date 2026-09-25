//! Backend-owned fixed endpoint profile registry.

use crate::ChatCompletionsProfile;

/// One immutable profile selected by exact provider ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericChatProfile {
    /// Provider ID.
    pub provider_id: &'static str,
    /// Exact profile ID.
    pub profile_id: &'static str,
    /// Profile-bound Chat Completions contract.
    pub profile: ChatCompletionsProfile,
}

#[path = "registry_data.rs"]
mod registry_data;

/// Returns one exact fixed endpoint profile.
#[must_use]
pub fn generic_profile(provider_id: &str) -> Option<ChatCompletionsProfile> {
    registry_data::PROFILES
        .iter()
        .find(|item| item.provider_id == provider_id)
        .map(|item| item.profile.clone())
}

/// Returns all fixed endpoint profiles.
#[must_use]
pub const fn generic_profiles() -> &'static [GenericChatProfile] {
    registry_data::PROFILES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChatCompletionsAccounting;
    use crate::ChatCompletionsRenderer;
    use runne_provider::{
        ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
        ProviderTerminalPricing, ProviderTextInput, ProviderUsage, TextProviderProfile,
    };
    use serde_json::Value;

    #[test]
    fn payg_profile_uses_pinned_rates_and_usd_currency() {
        let profile = generic_profile("openrouter").unwrap();
        let usage = ProviderUsage::new(1_000_000, 0, 0, 0).unwrap();
        assert_eq!(profile.currency(), "USD");
        assert_eq!(profile.price_usage_micros(usage).unwrap(), 800_000);
    }

    #[test]
    fn every_catalog_profile_has_content_bound_digests() {
        for entry in generic_profiles() {
            assert_eq!(
                entry.profile.profile_digest(),
                entry.profile.recomputed_profile_digest(),
                "{} profile",
                entry.provider_id
            );
            assert_eq!(
                entry.profile.pricing_revision_digest(),
                entry.profile.recomputed_pricing_revision_digest(),
                "{} pricing",
                entry.provider_id
            );
        }
    }

    #[test]
    fn every_fixed_profile_uses_the_verified_conservative_bounds() {
        assert_eq!(generic_profiles().len(), 23);
        for entry in generic_profiles() {
            assert_eq!(
                entry.profile.max_input_bytes(),
                65_536,
                "{} input",
                entry.provider_id
            );
            assert_eq!(
                entry.profile.max_input_entry_bytes(),
                65_536,
                "{} entry",
                entry.provider_id
            );
            assert_eq!(
                entry.profile.max_output_tokens(),
                16_384,
                "{} output",
                entry.provider_id
            );
        }
    }

    #[test]
    fn unpriced_profile_fails_closed_without_free_currency() {
        let profile = generic_profile("nvidia").unwrap();
        let usage = ProviderUsage::new(1, 1, 0, 0).unwrap();
        assert_eq!(profile.currency(), "XXX");
        assert!(profile.price_usage_micros(usage).is_err());
    }

    #[test]
    fn xiaomi_profile_uses_immutable_selected_model_rates() {
        let profile = generic_profile("xiaomi").unwrap();
        let usage = ProviderUsage::new(1_000_000, 1_000_000, 1_000_000, 0).unwrap();
        assert_eq!(profile.currency(), "USD");
        assert_eq!(profile.price_usage_micros(usage).unwrap(), 282_800);
    }

    #[test]
    fn payg_terminal_quote_rejects_each_wrong_digest() {
        let profile = generic_profile("openrouter").unwrap();
        let usage = ProviderUsage::new(1, 0, 0, 0).unwrap();
        let mut wrong_profile = profile.profile_digest();
        wrong_profile[0] ^= 1;
        assert!(
            profile
                .price_terminal_usage(&profile.pricing_revision_digest(), &wrong_profile, 0, usage,)
                .is_err()
        );
        let mut wrong_pricing = profile.pricing_revision_digest();
        wrong_pricing[0] ^= 1;
        assert!(
            profile
                .price_terminal_usage(&wrong_pricing, &profile.profile_digest(), 0, usage)
                .is_err()
        );
    }

    #[test]
    fn payg_proration_uses_ceiling_without_turning_zero_into_a_charge() {
        let profile = generic_profile("groq").unwrap();
        assert_eq!(
            profile
                .price_usage_micros(ProviderUsage::new(1, 0, 0, 0).unwrap())
                .unwrap(),
            1
        );
        assert_eq!(
            profile
                .price_usage_micros(ProviderUsage::new(0, 0, 0, 0).unwrap())
                .unwrap(),
            0
        );
    }

    #[test]
    fn changing_rates_changes_both_bound_digests() {
        let profile = generic_profile("openrouter").unwrap();
        let changed = ChatCompletionsProfile::new_with_accounting(
            "openrouter",
            "gocode-chat-completions/openrouter/1",
            "moonshotai/kimi-k2-0711-preview",
            "pi-ai-0.85.1-2026-09-05",
            "https://openrouter.ai/api",
            "/v1/chat/completions",
            [0; 32],
            [0; 32],
            profile.max_input_entries(),
            profile.max_input_entry_bytes(),
            profile.max_input_bytes(),
            profile.max_output_tokens(),
            profile.max_request_bytes(),
            profile.max_frame_bytes(),
            ChatCompletionsAccounting::Payg {
                input_micros_per_million: 801_000,
                output_micros_per_million: 1_600_000,
                cached_input_micros_per_million: 200_000,
            },
            profile.thinking_mode(),
        );
        assert_ne!(
            profile.recomputed_profile_digest(),
            changed.recomputed_profile_digest()
        );
        assert_ne!(
            profile.recomputed_pricing_revision_digest(),
            changed.recomputed_pricing_revision_digest()
        );
    }

    #[test]
    fn new_chat_profiles_pin_endpoint_billing_and_mistral_wire_quirk() {
        let fireworks = generic_profile("fireworks").unwrap();
        assert_eq!(fireworks.origin(), "https://api.fireworks.ai/inference/v1");
        assert_eq!(fireworks.path(), "/chat/completions");
        assert_eq!(fireworks.currency(), "USD");
        assert_eq!(
            fireworks
                .price_usage_micros(ProviderUsage::new(1_000_000, 0, 0, 0).unwrap())
                .unwrap(),
            150_000
        );

        let mistral = generic_profile("mistral").unwrap();
        assert_eq!(mistral.origin(), "https://api.mistral.ai");
        assert_eq!(mistral.path(), "/v1/chat/completions");
        assert!(!mistral.include_stream_usage());
        assert_eq!(
            mistral
                .price_usage_micros(ProviderUsage::new(1_000_000, 0, 0, 0).unwrap())
                .unwrap(),
            100_000
        );

        let opencode_go = generic_profile("opencode-go").unwrap();
        assert_eq!(opencode_go.origin(), "https://opencode.ai/zen/go/v1");
        assert_eq!(opencode_go.path(), "/chat/completions");
        assert_eq!(opencode_go.currency(), "XXX");
        assert!(
            opencode_go
                .price_usage_micros(ProviderUsage::new(1, 1, 0, 0).unwrap())
                .is_ok()
        );

        let renderer = ChatCompletionsRenderer::new(mistral.clone()).unwrap();
        let call = ProviderCall::new(
            ProviderCallId::from_bytes([7; 16]),
            ModelRef::new(
                ProviderId::new("mistral").unwrap(),
                mistral.model_id(),
                mistral.model_revision(),
            )
            .unwrap(),
            [9; 32],
            8,
            renderer.binding_extension(),
        )
        .unwrap()
        .with_text_inputs(vec![
            ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
        ])
        .unwrap()
        .with_required_capabilities(vec![ProviderCapability::Streaming]);
        let request: Value =
            serde_json::from_slice(renderer.prepare(&call).unwrap().rendered_bytes()).unwrap();
        assert!(request.get("stream_options").is_none());
    }
}
