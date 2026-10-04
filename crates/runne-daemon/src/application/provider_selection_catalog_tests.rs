use super::*;
use runne_api::{
    ProviderActivationBindingV1, ProviderActivationModeV1, ProviderCatalogEntryV1,
    ProviderCatalogRouteV1, ProviderImplementationStatusV1, provider_catalog,
    provider_catalog_entry,
};
use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderTextInput, TextProviderProfile,
};
use runne_provider_chat_completions::ChatCompletionsRenderer;
use runne_provider_deepseek::{DeepSeekResponsesTextProfile, DeepSeekResponsesTextRenderer};
use runne_provider_openai::{OpenAiResponsesTextProfile, OpenAiResponsesTextRenderer};
use runne_provider_responses_wire::prepare_call;

pub(super) fn call_for(
    profile: &dyn TextProviderProfile,
    model_id: &str,
    revision: &str,
) -> ProviderCall {
    let provider_id = if profile.profile_id().starts_with("gocode-chat-completions/")
        || profile.profile_id().starts_with("gocode-responses/")
        || profile.profile_id().starts_with("gocode-cloud/")
    {
        profile.profile_id().split('/').nth(1).unwrap_or_default()
    } else if profile.profile_id().starts_with("gocode-openai-") {
        "openai"
    } else if profile.profile_id().starts_with("gocode-zai-") {
        "zai"
    } else if profile.profile_id().starts_with("gocode-qwencloud-") {
        "qwen-token-plan-individual"
    } else {
        "deepseek"
    };
    ProviderCall::new(
        ProviderCallId::from_bytes([0x71; 16]),
        ModelRef::new(
            ProviderId::new(provider_id).expect("catalog provider id"),
            model_id,
            revision,
        )
        .expect("catalog model ref"),
        [0; 32],
        if profile
            .profile_id()
            .starts_with("gocode-responses/openai-codex/")
        {
            profile.max_output_tokens()
        } else {
            profile.max_output_tokens().min(256)
        },
        profile.call_binding_extension(),
    )
    .expect("call metadata")
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
    ])
    .expect("text context")
    .with_required_capabilities(vec![ProviderCapability::Streaming])
}

#[test]
fn every_fixed_chat_profile_selects_and_prepares_through_the_daemon_path() {
    for entry in runne_provider_chat_completions::generic_profiles() {
        let binding = ProviderActivationBindingV1::new(
            ProviderActivationModeV1::GenericChatCompletionsTextV1,
            entry.profile_id,
            entry.profile.profile_digest(),
        )
        .expect("registry binding");
        let activation = ProviderActivation::from_binding(binding);
        let selected = select_provider_runtime(&activation)
            .expect(entry.provider_id)
            .expect("selected runtime");
        assert_eq!(selected.provider_id, entry.provider_id);
        assert_eq!(selected.profile.profile_id(), entry.profile_id);
        let call = call_for(
            selected.profile.as_ref(),
            selected.model_id.as_ref(),
            selected.model_revision.as_ref(),
        );
        let prepared = ChatCompletionsRenderer::new(entry.profile.clone())
            .expect("validated renderer")
            .prepare(&call);
        assert!(prepared.is_ok(), "{} did not prepare", entry.provider_id);
    }
}

#[test]
fn dedicated_and_responses_profiles_select_and_prepare() {
    let openai = OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .unwrap();
    let openai_binding = ProviderActivationBindingV1::openai_responses_text_v1();
    let selected = select_provider_runtime(&ProviderActivation::from_binding(openai_binding))
        .unwrap()
        .unwrap();
    assert_eq!(selected.provider_id, "openai");
    assert!(
        OpenAiResponsesTextRenderer::new(openai)
            .prepare(&call_for(
                selected.profile.as_ref(),
                selected.model_id.as_ref(),
                selected.model_revision.as_ref(),
            ))
            .is_ok()
    );

    let deepseek = DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .unwrap();
    let selected = select_provider_runtime(&ProviderActivation::from_binding(
        ProviderActivationBindingV1::deepseek_responses_text_v1(),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(selected.provider_id, "deepseek");
    assert!(
        DeepSeekResponsesTextRenderer::new(deepseek)
            .prepare(&call_for(
                selected.profile.as_ref(),
                selected.model_id.as_ref(),
                selected.model_revision.as_ref(),
            ))
            .is_ok()
    );

    for profile in [
        runne_provider_zai::profile(),
        runne_provider_qwencloud::profile(),
    ] {
        let binding = ProviderActivationBindingV1::new(
            if profile.provider_id() == "zai" {
                ProviderActivationModeV1::ZaiCodingChatCompletionsTextV1
            } else {
                ProviderActivationModeV1::QwenCloudTokenChatCompletionsTextV1
            },
            profile.profile_id(),
            profile.profile_digest(),
        )
        .unwrap();
        let selected = select_provider_runtime(&ProviderActivation::from_binding(binding))
            .unwrap()
            .unwrap();
        assert!(
            ChatCompletionsRenderer::new(profile)
                .unwrap()
                .prepare(&call_for(
                    selected.profile.as_ref(),
                    selected.model_id.as_ref(),
                    selected.model_revision.as_ref(),
                ))
                .is_ok()
        );
    }

    for (profile_id, settings) in [
        (
            crate::provider_activation::responses::CODEX_PROFILE_ID,
            crate::provider_activation::ProviderActivationSettings::default(),
        ),
        (
            crate::provider_activation::responses::COPILOT_PROFILE_ID,
            crate::provider_activation::ProviderActivationSettings::default(),
        ),
        (
            crate::provider_activation::responses::XAI_PROFILE_ID,
            crate::provider_activation::ProviderActivationSettings {
                responses_pricing_digest: Some([7; 32]),
                responses_input_micros_per_million: Some(2_000_000),
                responses_output_micros_per_million: Some(10_000_000),
                ..Default::default()
            },
        ),
    ] {
        let (profile, _) =
            crate::provider_activation::configured_profile(profile_id, &settings).unwrap();
        let binding = ProviderActivationBindingV1::new(
            ProviderActivationModeV1::ResponsesTextV1,
            profile_id,
            profile.profile_digest(),
        )
        .unwrap();
        let selected = select_provider_runtime(&ProviderActivation::from_binding_with_settings(
            binding, settings,
        ))
        .unwrap()
        .unwrap();
        assert!(
            prepare_call(
                &profile,
                &call_for(
                    selected.profile.as_ref(),
                    selected.model_id.as_ref(),
                    selected.model_revision.as_ref(),
                ),
            )
            .is_ok()
        );
    }
}

#[test]
fn catalog_is_exactly_closed_and_each_entry_has_a_classification() {
    let expected = [
        "amazon-bedrock",
        "github-copilot",
        "nvidia",
        "vercel-ai-gateway",
        "anthropic",
        "google",
        "openai",
        "openai-background",
        "xai",
        "ant-ling",
        "google-vertex",
        "openai-codex",
        "xiaomi",
        "azure-openai-responses",
        "groq",
        "opencode",
        "xiaomi-token-plan-ams",
        "baseten",
        "huggingface",
        "opencode-go",
        "xiaomi-token-plan-cn",
        "cerebras",
        "kimi-coding",
        "openrouter",
        "xiaomi-token-plan-sgp",
        "cloudflare-ai-gateway",
        "minimax",
        "qwen-token-plan",
        "zai",
        "cloudflare-workers-ai",
        "minimax-cn",
        "qwen-token-plan-cn",
        "zai-coding-cn",
        "deepseek",
        "mistral",
        "qwen-token-plan-individual",
        "fireworks",
        "moonshotai",
        "moonshotai-cn",
        "radius",
        "together",
    ];
    assert_eq!(provider_catalog().len(), expected.len());
    for provider_id in expected {
        let entry: ProviderCatalogEntryV1 = provider_catalog_entry(provider_id).expect(provider_id);
        assert!(!entry.provider_id.is_empty());
        assert!(entry.auth_options.len() <= 2);
        assert!(matches!(
            entry.implementation,
            ProviderImplementationStatusV1::CatalogOnly
                | ProviderImplementationStatusV1::Implemented
        ));
        assert_ne!(entry.route(), ProviderCatalogRouteV1::CatalogOnly);
    }
}
