use super::*;
use crate::provider_activation::{ProviderAccountingMode, ProviderActivationSettings};
use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};
use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderTextInput, TextProviderProfile,
};

fn activation(profile_id: &str, settings: ProviderActivationSettings) -> ProviderActivation {
    let (profile, _) = crate::provider_activation::configured_profile(profile_id, &settings)
        .expect("closed Responses profile");
    let binding = ProviderActivationBindingV1::new(
        ProviderActivationModeV1::ResponsesTextV1,
        profile_id,
        profile.profile_digest(),
    )
    .expect("valid Responses binding");
    ProviderActivation::from_binding_with_settings(binding, settings)
}

#[test]
fn all_four_responses_profiles_select_a_bounded_runtime() {
    let cases = [
        (
            crate::provider_activation::responses::CODEX_PROFILE_ID,
            ProviderActivationSettings::default(),
        ),
        (
            crate::provider_activation::responses::COPILOT_PROFILE_ID,
            ProviderActivationSettings::default(),
        ),
        (
            crate::provider_activation::responses::XAI_PROFILE_ID,
            ProviderActivationSettings {
                responses_pricing_digest: Some([3; 32]),
                responses_input_micros_per_million: Some(2_000_000),
                responses_output_micros_per_million: Some(10_000_000),
                responses_cached_input_micros_per_million: Some(200_000),
                ..Default::default()
            },
        ),
    ];
    for (profile_id, settings) in cases {
        let selected = select_provider_runtime(&activation(profile_id, settings))
            .expect("selection")
            .expect("Responses runtime");
        assert_eq!(selected.profile.profile_id(), profile_id);
    }
    let azure_settings = ProviderActivationSettings {
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
    };
    let azure = activation(
        "gocode-responses/azure-openai-responses/gpt-5.5/1",
        azure_settings,
    );
    let selected = select_provider_runtime(&azure).unwrap().unwrap();
    assert_eq!(selected.provider_id, "azure-openai-responses");
}

#[test]
fn responses_profile_digest_is_recomputed_before_selection() {
    let binding = ProviderActivationBindingV1::new(
        ProviderActivationModeV1::ResponsesTextV1,
        crate::provider_activation::responses::CODEX_PROFILE_ID,
        [9; 32],
    )
    .unwrap();
    let activation = ProviderActivation::from_binding(binding);
    assert!(select_provider_runtime(&activation).is_err());
}

#[test]
fn pinned_subscription_profiles_match_reviewer_digests() {
    let codex = runne_provider_responses_wire::codex_subscription_profile(
        runne_provider_responses_wire::CODEX_MAX_OUTPUT_TOKENS,
        runne_provider_responses_wire::CODEX_SUBSCRIPTION_PRICING_DIGEST,
    );
    let copilot = runne_provider_responses_wire::copilot_subscription_profile(
        runne_provider_responses_wire::COPILOT_MAX_OUTPUT_TOKENS,
        runne_provider_responses_wire::COPILOT_SUBSCRIPTION_PRICING_DIGEST,
    );
    assert_eq!(
        hex::encode(codex.profile_digest()),
        "121fa4758fdc3c5d64c22d1edea1a3ea7ccc66ffeb3b87b5024d3254a705169c"
    );
    assert_eq!(
        hex::encode(copilot.profile_digest()),
        "0f26bba16768b8693cd931b253aa3e1bfa6378fda6227c5030b1a210a097195c"
    );
}

#[test]
fn responses_profiles_reject_subscription_billing_on_cloud_payg_routes() {
    let settings = ProviderActivationSettings {
        accounting_mode: Some(ProviderAccountingMode::Subscription),
        responses_pricing_digest: Some([3; 32]),
        responses_input_micros_per_million: Some(2_000_000),
        responses_output_micros_per_million: Some(10_000_000),
        ..Default::default()
    };
    assert!(
        crate::provider_activation::configured_profile(
            crate::provider_activation::responses::XAI_PROFILE_ID,
            &settings
        )
        .is_err()
    );
    let azure = ProviderActivationSettings {
        responses_resource: Some("tenant".into()),
        responses_deployment: Some("prod".into()),
        responses_pricing_digest: Some([4; 32]),
        responses_max_output_tokens: Some(16_384),
        responses_context_tokens: Some(128_000),
        accounting_mode: Some(ProviderAccountingMode::Subscription),
        ..Default::default()
    };
    assert!(
        crate::provider_activation::configured_profile(
            "gocode-responses/azure-openai-responses/gpt-5.5/1",
            &azure
        )
        .is_err()
    );
}

#[test]
fn selected_profile_extension_is_accepted_by_the_responses_renderer() {
    let activation = activation(
        crate::provider_activation::responses::CODEX_PROFILE_ID,
        ProviderActivationSettings::default(),
    );
    let selected = select_provider_runtime(&activation).unwrap().unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([8; 16]),
        ModelRef::new(
            ProviderId::new(selected.provider_id.as_ref()).unwrap(),
            selected.model_id.as_ref(),
            selected.model_revision.as_ref(),
        )
        .unwrap(),
        [7; 32],
        selected.profile.max_output_tokens(),
        selected.profile.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    let prepared = runne_provider_responses_wire::prepare_call(
        &runne_provider_responses_wire::codex_subscription_profile(
            selected.profile.max_output_tokens(),
            runne_provider_responses_wire::CODEX_SUBSCRIPTION_PRICING_DIGEST,
        ),
        &call,
    );
    assert!(prepared.is_ok());
}
