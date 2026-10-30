use runne_provider::{
    ModelRef, ProviderCall, ProviderCallDigestVersion, ProviderCallId, ProviderCapability,
    ProviderId, ProviderInputRole, ProviderTextInput, ProviderToolDeclarationV1,
    ProviderToolNameV1, ProviderToolResultV1, TextProviderProfile, ToolProviderProfile,
    canonical_provider_call_digest,
};
use runne_provider_deepseek::{
    DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION, DeepSeekResponsesTextProfile,
    DeepSeekResponsesTextRenderer, DeepSeekResponsesToolProfile, DeepSeekResponsesToolRenderer,
    DeepSeekToolRenderError,
};
use serde_json::Value;

const PROFILE_BYTES: &[u8] =
    include_bytes!("../../../docs/profiles/deepseek-responses-text-v1.json");

fn base_profile() -> DeepSeekResponsesTextProfile {
    DeepSeekResponsesTextProfile::from_json(PROFILE_BYTES).unwrap()
}

fn tool_call(profile: &DeepSeekResponsesToolProfile, output: &str) -> ProviderCall {
    let result = ProviderToolResultV1::new(
        "call_exact_1".to_owned(),
        ProviderToolNameV1::WorkspaceFileRead,
        r#"{"path":"notes.txt"}"#.to_owned(),
        output.to_owned(),
    )
    .unwrap();
    ProviderCall::new(
        ProviderCallId::from_bytes([7; 16]),
        ModelRef::new(
            ProviderId::new("deepseek").unwrap(),
            DEEPSEEK_MODEL_ID,
            DEEPSEEK_MODEL_REVISION,
        )
        .unwrap(),
        [9; 32],
        256,
        profile.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "inspect notes").unwrap(),
    ])
    .unwrap()
    .with_tool_context(profile.tool_declarations().to_vec(), vec![result])
    .unwrap()
    .with_required_capabilities(vec![
        ProviderCapability::Streaming,
        ProviderCapability::Tools,
    ])
}

#[test]
fn explicit_profile_renders_only_fixed_tools_and_correlated_result_items() {
    let profile = DeepSeekResponsesToolProfile::new(base_profile()).unwrap();
    let call = tool_call(&profile, r#"{"content":"approved"}"#);
    let prepared = DeepSeekResponsesToolRenderer::new(profile)
        .prepare(&call)
        .unwrap();
    let request: Value = serde_json::from_slice(prepared.rendered_bytes()).unwrap();
    assert_eq!(request["tool_choice"], "auto");
    assert_eq!(request["reasoning"]["effort"], "none");
    for unsupported in [
        "background",
        "store",
        "service_tier",
        "previous_response_id",
    ] {
        assert!(request.get(unsupported).is_none());
    }
    assert!(request["tools"][0].get("strict").is_none());
    assert_eq!(request["tools"].as_array().unwrap().len(), 6);
    assert_eq!(request["tools"][0]["name"], "workspace_file_read");
    assert_eq!(request["tools"][1]["name"], "workspace_file_create_new");
    assert_eq!(
        request["tools"][0]["parameters"],
        ProviderToolNameV1::WorkspaceFileRead.parameters()
    );
    assert_eq!(request["input"][1]["type"], "function_call");
    assert_eq!(request["input"][1]["name"], "workspace_file_read");
    assert_eq!(request["input"][1]["arguments"], r#"{"path":"notes.txt"}"#);
    assert_eq!(request["input"][2]["type"], "function_call_output");
    assert_eq!(request["input"][2]["call_id"], "call_exact_1");
    assert_eq!(request["input"][2]["output"], r#"{"content":"approved"}"#);
    assert_eq!(
        prepared.request_ref().digest_version(),
        ProviderCallDigestVersion::V2
    );
    assert!(prepared.render_digest() != &[0; 32]);
}

#[test]
fn renderer_accepts_profile_maximum_text_context_without_truncation() {
    let profile = DeepSeekResponsesToolProfile::new(base_profile()).unwrap();
    let inputs = (0..63)
        .map(|index| {
            let role = if index % 2 == 0 {
                ProviderInputRole::User
            } else {
                ProviderInputRole::Assistant
            };
            let bytes = if index == 62 { 8192 } else { 4096 };
            ProviderTextInput::new(role, "x".repeat(bytes)).unwrap()
        })
        .collect();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([9; 16]),
        ModelRef::new(
            ProviderId::new("deepseek").unwrap(),
            DEEPSEEK_MODEL_ID,
            DEEPSEEK_MODEL_REVISION,
        )
        .unwrap(),
        [9; 32],
        256,
        profile.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(inputs)
    .unwrap()
    .with_tool_context(profile.tool_declarations().to_vec(), vec![])
    .unwrap()
    .with_required_capabilities(vec![
        ProviderCapability::Streaming,
        ProviderCapability::Tools,
    ]);
    let prepared = DeepSeekResponsesToolRenderer::new(profile)
        .prepare(&call)
        .unwrap();
    let request: Value = serde_json::from_slice(prepared.rendered_bytes()).unwrap();
    assert_eq!(request["input"].as_array().unwrap().len(), 63);
    assert_eq!(
        request["input"][62]["content"][0]["text"]
            .as_str()
            .unwrap()
            .len(),
        8192
    );
}

#[test]
fn developer_canary_fails_before_a_tool_request_is_prepared_and_stays_out_of_errors() {
    const CANARY: &str = "M9-TOOL-RENDER-DEVELOPER-CANARY";

    let profile = DeepSeekResponsesToolProfile::new(base_profile()).unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([6; 16]),
        ModelRef::new(
            ProviderId::new("deepseek").unwrap(),
            DEEPSEEK_MODEL_ID,
            DEEPSEEK_MODEL_REVISION,
        )
        .unwrap(),
        [9; 32],
        256,
        profile.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::Developer, CANARY).unwrap(),
    ])
    .unwrap()
    .with_tool_context(profile.tool_declarations().to_vec(), vec![])
    .unwrap()
    .with_required_capabilities(vec![
        ProviderCapability::Streaming,
        ProviderCapability::Tools,
    ]);

    let result = DeepSeekResponsesToolRenderer::new(profile).prepare(&call);
    let Err(error) = result else {
        panic!("developer context must fail before a tool request is prepared");
    };
    assert_eq!(error, DeepSeekToolRenderError::InvalidCommittedContext);
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(
        !display.contains(CANARY),
        "display error exposed developer text"
    );
    assert!(
        !debug.contains(CANARY),
        "debug error exposed developer text"
    );
}

#[test]
fn text_profile_rejects_populated_tools_and_tool_profile_binds_result_identity() {
    let text = base_profile();
    let profile = DeepSeekResponsesToolProfile::new(text.clone()).unwrap();
    let call = tool_call(&profile, r#"{"content":"approved"}"#);
    let text_call = ProviderCall::new(
        ProviderCallId::from_bytes([8; 16]),
        ModelRef::new(
            ProviderId::new("deepseek").unwrap(),
            DEEPSEEK_MODEL_ID,
            DEEPSEEK_MODEL_REVISION,
        )
        .unwrap(),
        [9; 32],
        256,
        text.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "inspect").unwrap(),
    ])
    .unwrap()
    .with_tool_context(
        vec![ProviderToolDeclarationV1::for_name(
            ProviderToolNameV1::WorkspaceFileRead,
        )],
        vec![
            ProviderToolResultV1::new(
                "call_exact_1".to_owned(),
                ProviderToolNameV1::WorkspaceFileRead,
                "{}".to_owned(),
                "{}".to_owned(),
            )
            .unwrap(),
        ],
    )
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    assert_eq!(
        DeepSeekResponsesTextRenderer::new(text)
            .prepare(&text_call)
            .unwrap_err(),
        runne_provider_deepseek::DeepSeekRenderError::UnsupportedCapability
    );
    let changed = tool_call(&profile, r#"{"content":"different"}"#);
    assert_ne!(
        canonical_provider_call_digest(&call).unwrap(),
        canonical_provider_call_digest(&changed).unwrap()
    );
    assert_ne!(
        DeepSeekResponsesToolRenderer::new(profile.clone())
            .prepare(&call)
            .unwrap()
            .render_digest(),
        DeepSeekResponsesToolRenderer::new(profile)
            .prepare(&changed)
            .unwrap()
            .render_digest()
    );
}

#[test]
fn tool_profile_rejects_unknown_declarations_and_unbounded_results() {
    let profile = DeepSeekResponsesToolProfile::new(base_profile()).unwrap();
    let unknown = ProviderToolDeclarationV1::for_name(ProviderToolNameV1::WorkspaceFileRead);
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([7; 16]),
        ModelRef::new(
            ProviderId::new("deepseek").unwrap(),
            DEEPSEEK_MODEL_ID,
            DEEPSEEK_MODEL_REVISION,
        )
        .unwrap(),
        [9; 32],
        8,
        profile.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "x").unwrap(),
    ])
    .unwrap()
    .with_tool_context(vec![unknown], vec![])
    .unwrap()
    .with_required_capabilities(vec![
        ProviderCapability::Streaming,
        ProviderCapability::Tools,
    ]);
    assert_eq!(
        DeepSeekResponsesToolRenderer::new(profile)
            .prepare(&call)
            .unwrap_err(),
        DeepSeekToolRenderError::UnsupportedToolContext
    );
    assert!(
        ProviderToolResultV1::new(
            "call".to_owned(),
            ProviderToolNameV1::WorkspaceFileRead,
            "{}".to_owned(),
            "x".repeat(16 * 1024 + 1)
        )
        .is_err()
    );
}
