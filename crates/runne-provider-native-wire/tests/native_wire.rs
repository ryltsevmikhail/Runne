use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderFinishReason, ProviderId,
    ProviderInputRole, ProviderStreamEvent, ProviderStreamEventKind, ProviderTerminalDisposition,
    ProviderTerminalPricing, ProviderTextInput, ProviderUsage, TextProviderProfile,
};
use runne_provider_native_wire::{
    AnthropicMessagesProfile, AnthropicMessagesRenderer, AnthropicStreamDecoder,
    AnthropicStreamError, GeminiProfile, GeminiRenderer, GeminiStreamDecoder, GeminiStreamError,
    NativeAccounting, WireLimits,
};
use serde_json::{Value, json};

#[path = "native_wire/accounting.rs"]
mod accounting;

fn limits() -> WireLimits {
    WireLimits::new(8, 128, 512, 256, 4096, 2048).unwrap()
}

fn profiles() -> (AnthropicMessagesProfile, GeminiProfile) {
    (
        AnthropicMessagesProfile::new(
            "anthropic",
            "anthropic-text/1",
            "claude-native-test",
            "2026-09-14",
            [1; 32],
            [2; 32],
            limits(),
        )
        .unwrap(),
        GeminiProfile::new(
            "google",
            "gemini-text/1",
            "gemini-native-test",
            "2026-09-14",
            [3; 32],
            [4; 32],
            limits(),
        )
        .unwrap(),
    )
}

fn call(
    provider: &str,
    model: &str,
    revision: &str,
    extension: Value,
    inputs: Vec<ProviderTextInput>,
) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([7; 16]),
        ModelRef::new(ProviderId::new(provider).unwrap(), model, revision).unwrap(),
        [9; 32],
        32,
        extension,
    )
    .unwrap()
    .with_text_inputs(inputs)
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming])
}

fn text(role: ProviderInputRole, value: &str) -> ProviderTextInput {
    ProviderTextInput::new(role, value).unwrap()
}

fn decode_anthropic(wire: &[u8]) -> Result<Vec<ProviderStreamEvent>, AnthropicStreamError> {
    let (profile, _) = profiles();
    let mut decoder = AnthropicStreamDecoder::for_profile(&profile);
    for byte in wire {
        decoder.push(std::slice::from_ref(byte))?;
    }
    decoder.finish()
}
fn decode_gemini(wire: &[u8]) -> Result<Vec<ProviderStreamEvent>, GeminiStreamError> {
    let (_, profile) = profiles();
    let mut decoder = GeminiStreamDecoder::for_profile(&profile);
    for byte in wire {
        decoder.push(std::slice::from_ref(byte))?;
    }
    decoder.finish()
}

fn text_output(events: &[ProviderStreamEvent]) -> String {
    events
        .iter()
        .filter_map(|event| match event.kind() {
            ProviderStreamEventKind::TextDelta { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn assert_credential_free(bytes: &[u8]) {
    let body = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for forbidden in ["authorization", "bearer", "api_key", "secret_ref"] {
        assert!(
            !body.contains(forbidden),
            "rendered body contains {forbidden}"
        );
    }
}

#[test]
fn anthropic_fixture_renders_and_decodes_with_fragmentation_and_usage_math() {
    let (profile, _) = profiles();
    let request = AnthropicMessagesRenderer::new(profile.clone())
        .prepare(&call(
            "anthropic",
            "claude-native-test",
            "2026-09-14",
            profile.binding_extension(),
            vec![text(ProviderInputRole::User, "hello")],
        ))
        .unwrap();
    let body: Value = serde_json::from_slice(request.rendered_bytes()).unwrap();
    assert_eq!(body["model"], "claude-native-test");
    assert_eq!(body["messages"][0]["content"], "hello");
    assert_eq!(body["stream"], true);
    assert_credential_free(request.rendered_bytes());
    let events = decode_anthropic(include_bytes!("fixtures/anthropic_messages.sse")).unwrap();
    assert_eq!(text_output(&events), "Привет!");
    let usage = events
        .iter()
        .find_map(|event| match event.kind() {
            ProviderStreamEventKind::Usage { usage } => Some(usage),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        (
            usage.input_tokens(),
            usage.cached_input_tokens(),
            usage.output_tokens(),
            usage.reasoning_output_tokens()
        ),
        (12, 2, 4, 0)
    );
    assert!(matches!(
        events.last().unwrap().kind(),
        ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::Completed,
            reason: ProviderFinishReason::Stop
        }
    ));
}

#[test]
fn gemini_fixture_renders_and_decodes_with_fragmentation_and_reasoning_usage() {
    let (_, profile) = profiles();
    let request = GeminiRenderer::new(profile.clone())
        .prepare(&call(
            "google",
            "gemini-native-test",
            "2026-09-14",
            profile.binding_extension(),
            vec![text(ProviderInputRole::User, "hello")],
        ))
        .unwrap();
    let body: Value = serde_json::from_slice(request.rendered_bytes()).unwrap();
    assert_eq!(body["contents"][0]["role"], "user");
    assert_eq!(body["generationConfig"]["maxOutputTokens"], 32);
    assert_credential_free(request.rendered_bytes());
    let events = decode_gemini(include_bytes!("fixtures/gemini_stream.sse")).unwrap();
    assert_eq!(text_output(&events), "Gemini");
    let usage = events
        .iter()
        .find_map(|event| match event.kind() {
            ProviderStreamEventKind::Usage { usage } => Some(usage),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        (
            usage.input_tokens(),
            usage.cached_input_tokens(),
            usage.output_tokens(),
            usage.reasoning_output_tokens()
        ),
        (12, 2, 5, 1)
    );
    assert!(matches!(
        events.last().unwrap().kind(),
        ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::Completed,
            reason: ProviderFinishReason::Stop
        }
    ));
}

#[test]
fn renderers_reject_tools_developer_and_binding_mutation() {
    let (anthropic, gemini) = profiles();
    let mut extension = anthropic.binding_extension();
    extension["extra"] = json!(true);
    let bad = call(
        "anthropic",
        "claude-native-test",
        "2026-09-14",
        extension,
        vec![text(ProviderInputRole::User, "hello")],
    );
    assert!(matches!(
        AnthropicMessagesRenderer::new(anthropic.clone()).prepare(&bad),
        Err(runne_provider_native_wire::AnthropicRenderError::ForbiddenExtension)
    ));
    let developer = call(
        "google",
        "gemini-native-test",
        "2026-09-14",
        gemini.binding_extension(),
        vec![text(ProviderInputRole::Developer, "hidden")],
    );
    assert!(matches!(
        GeminiRenderer::new(gemini).prepare(&developer),
        Err(runne_provider_native_wire::GeminiRenderError::InvalidContext)
    ));
    let tools = call(
        "anthropic",
        "claude-native-test",
        "2026-09-14",
        anthropic.binding_extension(),
        vec![text(ProviderInputRole::User, "hello")],
    )
    .with_required_capabilities(vec![
        ProviderCapability::Streaming,
        ProviderCapability::Tools,
    ]);
    assert!(matches!(
        AnthropicMessagesRenderer::new(anthropic).prepare(&tools),
        Err(runne_provider_native_wire::AnthropicRenderError::UnsupportedCapability)
    ));
}
