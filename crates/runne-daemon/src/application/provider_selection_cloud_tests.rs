use super::*;
use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};
use runne_provider::TextProviderProfile;
use runne_provider_chat_completions::ChatCompletionsRenderer;

fn settings(gateway: bool) -> crate::provider_activation::ProviderActivationSettings {
    crate::provider_activation::ProviderActivationSettings {
        cloud_region_or_account: Some(if gateway { "acct" } else { "us-east-1" }.into()),
        cloud_gateway: gateway.then(|| "runne".into()),
        cloud_input_micros_per_million: Some(2_000_000),
        cloud_output_micros_per_million: Some(10_000_000),
        cloud_cached_input_micros_per_million: Some(200_000),
        cloud_context_tokens: Some(32_768),
        cloud_max_output_tokens: Some(4_096),
        cloud_max_model_output_tokens: Some(8_192),
        cloud_max_input_entries: Some(64),
        cloud_max_input_entry_bytes: Some(8_192),
        cloud_max_input_bytes: Some(16_384),
        cloud_max_request_bytes: Some(32 * 1024),
        cloud_max_response_frame_bytes: Some(32 * 1024),
        cloud_gateway_billing: gateway.then(|| "stored_byok".into()),
        accounting_mode: Some(crate::provider_activation::ProviderAccountingMode::Payg),
        ..Default::default()
    }
}

#[test]
fn cloud_mode_11_selects_and_prepares_real_model_ids() {
    for (profile_id, gateway) in [
        (
            "gocode-cloud/amazon-bedrock/anthropic.claude-3-5-sonnet/1",
            false,
        ),
        (
            "gocode-cloud/cloudflare-workers-ai/@cf/meta/llama-3.1-8b-instruct/1",
            false,
        ),
        ("gocode-cloud/cloudflare-ai-gateway/openai/gpt-4o/1", true),
        ("gocode-cloud/nvidia/meta/llama-3.1-8b-instruct/1", false),
    ] {
        let settings = settings(gateway);
        let (profile, _) =
            crate::provider_activation::cloud::configured_profile(profile_id, &settings).unwrap();
        let binding = ProviderActivationBindingV1::new(
            ProviderActivationModeV1::CloudTextV1,
            profile_id,
            profile.profile_digest(),
        )
        .unwrap();
        let activation = ProviderActivation::from_binding_with_settings(binding, settings);
        let selected = select_provider_runtime(&activation).unwrap().unwrap();
        assert_eq!(selected.profile.profile_id(), profile_id);
        assert!(
            ChatCompletionsRenderer::new(profile)
                .unwrap()
                .prepare(&super::catalog_tests::call_for(
                    selected.profile.as_ref(),
                    selected.model_id.as_ref(),
                    selected.model_revision.as_ref(),
                ))
                .is_ok()
        );
    }
}

#[test]
fn cloud_mode_rejects_missing_owner_model_bound() {
    let mut config = settings(false);
    config.cloud_max_model_output_tokens = None;
    assert!(
        crate::provider_activation::cloud::configured_profile(
            "gocode-cloud/nvidia/meta/llama-3.1-8b-instruct/1",
            &config
        )
        .is_err()
    );
}
