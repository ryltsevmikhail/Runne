use super::super::*;
use crate::provider_activation::{ProviderAccountingMode, ProviderActivationSettings};
use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};
use runne_provider_radius::RadiusCatalog;
use std::collections::BTreeSet;

use super::expected::EXPECTED_IDS;
use super::support::{
    RADIUS_CATALOG, assert_selects_and_prepares, cloud_settings, generic_binding, native_binding,
    vertex_digest,
};

#[test]
fn closed_catalog_ids_all_select_and_prepare_without_credentials() {
    let mut seen = BTreeSet::new();
    for profile in runne_provider_chat_completions::generic_profiles() {
        assert_selects_and_prepares(generic_binding(profile), profile.provider_id);
        seen.insert(profile.provider_id);
    }
    for (mode, profile) in [
        (
            ProviderActivationModeV1::OpenAiResponsesTextV1,
            runne_provider_openai::OPENAI_RESPONSES_PROFILE_ID,
        ),
        (
            ProviderActivationModeV1::DeepSeekResponsesTextV1,
            runne_provider_deepseek::DEEPSEEK_RESPONSES_PROFILE_ID,
        ),
    ] {
        let binding = if mode == ProviderActivationModeV1::OpenAiResponsesTextV1 {
            ProviderActivationBindingV1::openai_responses_text_v1()
        } else {
            ProviderActivationBindingV1::deepseek_responses_text_v1()
        };
        let expected = if mode == ProviderActivationModeV1::OpenAiResponsesTextV1 {
            "openai"
        } else {
            "deepseek"
        };
        assert_eq!(binding.profile_id(), profile);
        assert_selects_and_prepares(ProviderActivation::from_binding(binding), expected);
        seen.insert(expected);
    }
    for (profile, mode, expected) in [
        (
            runne_provider_zai::profile(),
            ProviderActivationModeV1::ZaiCodingChatCompletionsTextV1,
            "zai",
        ),
        (
            runne_provider_qwencloud::profile(),
            ProviderActivationModeV1::QwenCloudTokenChatCompletionsTextV1,
            "qwen-token-plan-individual",
        ),
    ] {
        let binding =
            ProviderActivationBindingV1::new(mode, profile.profile_id(), profile.profile_digest())
                .unwrap();
        assert_selects_and_prepares(ProviderActivation::from_binding(binding), expected);
        seen.insert(expected);
    }
    for (profile_id, settings, expected) in [
        (
            crate::provider_activation::responses::CODEX_PROFILE_ID,
            ProviderActivationSettings::default(),
            "openai-codex",
        ),
        (
            crate::provider_activation::responses::COPILOT_PROFILE_ID,
            ProviderActivationSettings::default(),
            "github-copilot",
        ),
        (
            crate::provider_activation::responses::XAI_PROFILE_ID,
            ProviderActivationSettings {
                responses_pricing_digest: Some([3; 32]),
                responses_input_micros_per_million: Some(2_000_000),
                responses_output_micros_per_million: Some(10_000_000),
                responses_cached_input_micros_per_million: Some(200_000),
                accounting_mode: Some(ProviderAccountingMode::Payg),
                ..Default::default()
            },
            "xai",
        ),
        (
            "gocode-responses/azure-openai-responses/gpt-5.5/1",
            ProviderActivationSettings {
                responses_resource: Some("tenant".into()),
                responses_deployment: Some("prod".into()),
                responses_pricing_digest: Some([4; 32]),
                responses_input_micros_per_million: Some(2_000_000),
                responses_output_micros_per_million: Some(10_000_000),
                responses_cached_input_micros_per_million: Some(200_000),
                responses_max_output_tokens: Some(16_384),
                responses_context_tokens: Some(128_000),
                accounting_mode: Some(ProviderAccountingMode::Payg),
                ..Default::default()
            },
            "azure-openai-responses",
        ),
    ] {
        let (profile, _) =
            crate::provider_activation::responses::configured_profile(profile_id, &settings)
                .unwrap();
        let binding = ProviderActivationBindingV1::new(
            ProviderActivationModeV1::ResponsesTextV1,
            profile_id,
            profile.profile_digest(),
        )
        .unwrap();
        assert_selects_and_prepares(
            ProviderActivation::from_binding_with_settings(binding, settings),
            expected,
        );
        seen.insert(expected);
    }
    for (profile_id, expected, settings) in [
        (
            "gocode-responses/openai-codex/gpt-5.5/1",
            "openai-codex",
            ProviderActivationSettings::default(),
        ),
        (
            "gocode-responses/github-copilot/gpt-5.3-codex/1",
            "github-copilot",
            ProviderActivationSettings::default(),
        ),
        (
            "gocode-responses/xai/grok-4.3/1",
            "xai",
            ProviderActivationSettings {
                responses_pricing_digest: Some([7; 32]),
                responses_input_micros_per_million: Some(2_000_000),
                responses_output_micros_per_million: Some(10_000_000),
                responses_cached_input_micros_per_million: Some(200_000),
                accounting_mode: Some(ProviderAccountingMode::Payg),
                ..Default::default()
            },
        ),
        (
            "gocode-responses/azure-openai-responses/gpt-5.5/1",
            "azure-openai-responses",
            ProviderActivationSettings {
                responses_resource: Some("runne-fixture".into()),
                responses_deployment: Some("gpt-deployment".into()),
                responses_pricing_digest: Some([8; 32]),
                responses_input_micros_per_million: Some(2_000_000),
                responses_output_micros_per_million: Some(10_000_000),
                responses_cached_input_micros_per_million: Some(200_000),
                responses_max_output_tokens: Some(16_384),
                responses_context_tokens: Some(128_000),
                accounting_mode: Some(ProviderAccountingMode::Payg),
                ..Default::default()
            },
        ),
    ] {
        let (profile, _) = crate::provider_activation::configured_profile(profile_id, &settings)
            .unwrap_or_else(|error| panic!("{profile_id}: {error}"));
        let binding = ProviderActivationBindingV1::new(
            ProviderActivationModeV1::ResponsesTextV1,
            profile_id,
            profile.profile_digest(),
        )
        .unwrap();
        assert_selects_and_prepares(
            ProviderActivation::from_binding_with_settings(binding, settings),
            expected,
        );
        seen.insert(expected);
    }
    for (id, digest, accounting) in [
        (
            runne_api::NATIVE_ANTHROPIC_PROFILE_ID,
            runne_api::NATIVE_ANTHROPIC_PROFILE_DIGEST,
            None,
        ),
        (
            runne_api::NATIVE_GOOGLE_PROFILE_ID,
            runne_api::NATIVE_GOOGLE_PROFILE_DIGEST,
            None,
        ),
        (
            runne_api::NATIVE_KIMI_PROFILE_ID,
            runne_api::NATIVE_KIMI_PROFILE_DIGEST,
            None,
        ),
        (
            runne_api::NATIVE_VERCEL_PROFILE_ID,
            runne_api::NATIVE_VERCEL_PROFILE_DIGEST,
            None,
        ),
        (
            runne_api::NATIVE_MINIMAX_PROFILE_ID,
            runne_api::NATIVE_MINIMAX_PROFILE_DIGEST,
            Some(ProviderAccountingMode::Payg),
        ),
        (
            runne_api::NATIVE_MINIMAX_CN_PROFILE_ID,
            runne_api::NATIVE_MINIMAX_CN_PROFILE_DIGEST,
            Some(ProviderAccountingMode::Payg),
        ),
    ] {
        let activation = native_binding(id, digest);
        let activation = accounting.map_or(activation.clone(), |mode| {
            ProviderActivation::from_binding_with_settings(
                activation.binding().clone(),
                ProviderActivationSettings {
                    accounting_mode: Some(mode),
                    ..Default::default()
                },
            )
        });
        assert_selects_and_prepares(activation, id.split('/').nth(1).unwrap());
        seen.insert(id.split('/').nth(1).unwrap());
    }
    let project = "runne-fixture";
    let location = "us-central1";
    assert_selects_and_prepares(
        ProviderActivation::from_binding_with_settings(
            ProviderActivationBindingV1::new(
                ProviderActivationModeV1::NativeTextV1,
                runne_api::NATIVE_VERTEX_PROFILE_ID,
                vertex_digest(project, location),
            )
            .unwrap(),
            ProviderActivationSettings {
                vertex_project: Some(project.into()),
                vertex_location: Some(location.into()),
                ..Default::default()
            },
        ),
        "google-vertex",
    );
    seen.insert("google-vertex");
    for (id, gateway) in [
        ("amazon-bedrock", false),
        ("cloudflare-workers-ai", false),
        ("cloudflare-ai-gateway", true),
        ("nvidia", false),
    ] {
        let profile_id = match id {
            "amazon-bedrock" => "gocode-cloud/amazon-bedrock/anthropic.claude-3-5-sonnet/1",
            "cloudflare-workers-ai" => {
                "gocode-cloud/cloudflare-workers-ai/@cf/meta/llama-3.1-8b-instruct/1"
            }
            "cloudflare-ai-gateway" => "gocode-cloud/cloudflare-ai-gateway/openai/gpt-4o/1",
            _ => "gocode-cloud/nvidia/meta/llama-3.1-8b-instruct/1",
        };
        let settings = cloud_settings(gateway);
        let (profile, _) =
            crate::provider_activation::cloud::configured_profile(profile_id, &settings).unwrap();
        let binding = ProviderActivationBindingV1::new(
            ProviderActivationModeV1::CloudTextV1,
            profile_id,
            profile.profile_digest(),
        )
        .unwrap();
        assert_selects_and_prepares(
            ProviderActivation::from_binding_with_settings(binding, settings),
            id,
        );
        seen.insert(id);
    }
    let radius = RadiusCatalog::from_json_at(RADIUS_CATALOG, "https://radius.pi.dev")
        .unwrap()
        .select("radius", "fixture-model", "fixture-rev")
        .unwrap();
    let binding = ProviderActivationBindingV1::new(
        ProviderActivationModeV1::RadiusTextV1,
        runne_api::RADIUS_TEXT_PROFILE_ID,
        radius.profile_digest(),
    )
    .unwrap();
    assert_selects_and_prepares(
        ProviderActivation::from_binding_with_settings(
            binding,
            ProviderActivationSettings {
                radius_catalog: Some(RADIUS_CATALOG.to_vec()),
                radius_model_id: Some("fixture-model".into()),
                radius_revision: Some("fixture-rev".into()),
                ..Default::default()
            },
        ),
        "radius",
    );
    seen.insert("radius");
    assert_eq!(seen, EXPECTED_IDS.iter().copied().collect());
}
