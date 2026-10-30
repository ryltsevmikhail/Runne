use runne_daemon_deepseek_effect::{DeepSeekEffect, effect_from_loopback_fixture};

fn accepts_only_sealed_effect(_: &dyn DeepSeekEffect) {}

#[test]
fn explicit_client_constructor_returns_only_the_sealed_effect_object() {
    let client = reqwest::Client::builder().https_only(true).build().unwrap();
    let (effect, _) = effect_from_loopback_fixture(client).unwrap();
    accepts_only_sealed_effect(effect.as_ref());
}

#[test]
fn tool_sender_preparation_requires_distinct_bound_profile() {
    use runne_provider::{
        ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
        ProviderTextInput, TextProviderProfile, ToolProviderProfile,
    };
    use runne_provider_deepseek::{
        DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION, DeepSeekResponsesTextProfile,
        DeepSeekResponsesToolProfile,
    };
    let text = DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .unwrap();
    let tool = DeepSeekResponsesToolProfile::new(text.clone()).unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([1; 16]),
        ModelRef::new(
            ProviderId::new("deepseek").unwrap(),
            DEEPSEEK_MODEL_ID,
            DEEPSEEK_MODEL_REVISION,
        )
        .unwrap(),
        [2; 32],
        64,
        tool.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "inspect workspace").unwrap(),
    ])
    .unwrap()
    .with_tool_context(tool.tool_declarations().to_vec(), vec![])
    .unwrap()
    .with_required_capabilities(vec![
        ProviderCapability::Streaming,
        ProviderCapability::Tools,
    ]);
    let client = reqwest::Client::builder().https_only(true).build().unwrap();
    let (text_sender, _) = effect_from_loopback_fixture(client.clone()).unwrap();
    let (tool_sender, _) =
        runne_daemon_deepseek_effect::tool_effect_from_loopback_fixture(client).unwrap();
    assert!(text_sender.prepare(&call).is_err());
    let prepared = tool_sender.prepare(&call).unwrap();
    let request: serde_json::Value = serde_json::from_slice(prepared.rendered_bytes()).unwrap();
    assert_eq!(request["tool_choice"], "auto");
    assert_ne!(tool.profile_digest(), text.profile_digest());
}
