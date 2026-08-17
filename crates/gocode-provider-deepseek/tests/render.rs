use gocode_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderTextInput,
};
use gocode_provider_deepseek::{
    DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION, DeepSeekRenderError, DeepSeekResponsesTextProfile,
    DeepSeekResponsesTextRenderer,
};
use serde_json::{Value, json};

const PROFILE_BYTES: &[u8] =
    include_bytes!("../../../docs/profiles/deepseek-responses-text-v1.json");
const GOLDEN_REQUEST: &[u8] =
    include_bytes!("../../../docs/golden/deepseek-responses-text-request-v1.json");

fn profile() -> DeepSeekResponsesTextProfile {
    DeepSeekResponsesTextProfile::from_json(PROFILE_BYTES).unwrap()
}

fn call_with(
    inputs: Vec<ProviderTextInput>,
    max_output_tokens: u32,
    capabilities: Vec<ProviderCapability>,
    extension: Value,
) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([7; 16]),
        ModelRef::new(
            ProviderId::new("deepseek").unwrap(),
            DEEPSEEK_MODEL_ID,
            DEEPSEEK_MODEL_REVISION,
        )
        .unwrap(),
        [9; 32],
        max_output_tokens,
        extension,
    )
    .unwrap()
    .with_text_inputs(inputs)
    .unwrap()
    .with_required_capabilities(capabilities)
}

fn text(role: ProviderInputRole, value: &str) -> ProviderTextInput {
    ProviderTextInput::new(role, value).unwrap()
}

fn valid_call(profile: &DeepSeekResponsesTextProfile) -> ProviderCall {
    call_with(
        vec![text(ProviderInputRole::User, "hello")],
        1,
        vec![ProviderCapability::Streaming],
        profile.binding_extension(),
    )
}

#[test]
fn renderer_emits_exact_literal_credential_free_golden_bytes() {
    let profile = profile();
    let prepared = DeepSeekResponsesTextRenderer::new(profile.clone())
        .prepare(&valid_call(&profile))
        .unwrap();

    assert_eq!(prepared.rendered_bytes(), GOLDEN_REQUEST);
    assert_eq!(
        prepared.request_ref().digest_version(),
        gocode_provider::ProviderCallDigestVersion::V2
    );
    let lower = String::from_utf8_lossy(prepared.rendered_bytes()).to_ascii_lowercase();
    let value: Value = serde_json::from_slice(prepared.rendered_bytes()).unwrap();
    assert_eq!(value["service_tier"], "default");
    for forbidden in [
        "authorization",
        "bearer",
        "credential",
        "api_key",
        "secret_ref",
    ] {
        assert!(!lower.contains(forbidden), "found {forbidden}");
    }
}

#[test]
fn committed_history_order_and_roles_are_preserved_without_hidden_prompt() {
    let profile = profile();
    let call = call_with(
        vec![
            text(ProviderInputRole::User, "first"),
            text(ProviderInputRole::Assistant, "answer"),
            text(ProviderInputRole::User, "последний\nline"),
        ],
        64,
        vec![ProviderCapability::Streaming],
        profile.binding_extension(),
    );
    let prepared = DeepSeekResponsesTextRenderer::new(profile)
        .prepare(&call)
        .unwrap();
    let value: Value = serde_json::from_slice(prepared.rendered_bytes()).unwrap();

    assert_eq!(value["input"].as_array().unwrap().len(), 3);
    assert_eq!(value["input"][0]["role"], "user");
    assert_eq!(value["input"][0]["content"][0]["type"], "input_text");
    assert_eq!(value["input"][1]["role"], "assistant");
    assert_eq!(value["input"][1]["content"][0]["type"], "output_text");
    assert_eq!(value["input"][2]["content"][0]["text"], "последний\nline");
    assert!(
        !prepared
            .rendered_bytes()
            .windows(b"developer".len())
            .any(|window| window == b"developer")
    );
}

#[test]
fn empty_wrong_sequence_developer_and_output_overflow_fail_before_render() {
    let profile = profile();
    let cases = [
        (Vec::new(), 1, DeepSeekRenderError::EmptyCommittedContext),
        (
            vec![text(ProviderInputRole::Assistant, "orphan")],
            1,
            DeepSeekRenderError::InvalidCommittedContext,
        ),
        (
            vec![
                text(ProviderInputRole::User, "one"),
                text(ProviderInputRole::User, "two"),
            ],
            1,
            DeepSeekRenderError::InvalidCommittedContext,
        ),
        (
            vec![text(ProviderInputRole::Developer, "hidden")],
            1,
            DeepSeekRenderError::DeveloperPromptForbidden,
        ),
        (
            vec![text(ProviderInputRole::User, "hello")],
            16_385,
            DeepSeekRenderError::ContextLimitExceeded,
        ),
    ];
    for (inputs, max_output_tokens, expected) in cases {
        let call = call_with(
            inputs,
            max_output_tokens,
            vec![ProviderCapability::Streaming],
            profile.binding_extension(),
        );
        assert_eq!(
            DeepSeekResponsesTextRenderer::new(profile.clone()).prepare(&call),
            Err(expected)
        );
    }
}

#[test]
fn unsupported_capability_model_and_extension_mutation_fail_closed() {
    let profile = profile();
    let unsupported = call_with(
        vec![text(ProviderInputRole::User, "hello")],
        1,
        vec![ProviderCapability::Streaming, ProviderCapability::Tools],
        profile.binding_extension(),
    );
    assert_eq!(
        DeepSeekResponsesTextRenderer::new(profile.clone()).prepare(&unsupported),
        Err(DeepSeekRenderError::UnsupportedCapability)
    );

    let mut extension = profile.binding_extension();
    extension["fallback_profile"] = json!("deterministic");
    let forbidden = call_with(
        vec![text(ProviderInputRole::User, "hello")],
        1,
        vec![ProviderCapability::Streaming],
        extension,
    );
    assert_eq!(
        DeepSeekResponsesTextRenderer::new(profile.clone()).prepare(&forbidden),
        Err(DeepSeekRenderError::ForbiddenExtension)
    );

    let wrong_model = ProviderCall::new(
        ProviderCallId::from_bytes([8; 16]),
        ModelRef::new(
            ProviderId::new("deepseek").unwrap(),
            "deepseek-chat",
            "latest",
        )
        .unwrap(),
        [9; 32],
        1,
        profile.binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![text(ProviderInputRole::User, "hello")])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    assert_eq!(
        DeepSeekResponsesTextRenderer::new(profile).prepare(&wrong_model),
        Err(DeepSeekRenderError::ProfileBindingMismatch)
    );
}

#[test]
fn renderer_accepts_exact_maximum_history_without_truncation() {
    let profile = profile();
    let inputs = (0..63)
        .map(|index| {
            let role = if index % 2 == 0 {
                ProviderInputRole::User
            } else {
                ProviderInputRole::Assistant
            };
            text(role, "x")
        })
        .collect();
    let call = call_with(
        inputs,
        16_384,
        vec![ProviderCapability::Streaming],
        profile.binding_extension(),
    );

    let prepared = DeepSeekResponsesTextRenderer::new(profile)
        .prepare(&call)
        .unwrap();
    let value: Value = serde_json::from_slice(prepared.rendered_bytes()).unwrap();
    assert_eq!(value["input"].as_array().unwrap().len(), 63);
    assert_eq!(value["max_output_tokens"], 16_384);
}
