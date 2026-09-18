use super::*;
use crate::{ResponsesProfile, ResponsesProvider};
#[test]
fn renders_subscription_safe_text_request() {
    let profile = ResponsesProfile::new(ResponsesProvider::OpenAiCodex, "gpt-5.2");
    let body = render_request(
        &profile,
        &ResponsesRequest {
            input: vec![PromptTurn {
                role: "user".into(),
                text: "hello".into(),
            }],
            max_output_tokens: 32,
            instructions: Some("be concise".into()),
        },
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["model"], "gpt-5.2");
    assert_eq!(value["store"], false);
    assert_eq!(value["stream"], true);
    assert!(value.get("tools").is_none());
    assert!(value.get("reasoning").is_none());
    assert!(value.get("tool_choice").is_none());
}
#[test]
fn rejects_non_text_shape_and_bounds() {
    let p = ResponsesProfile::new(ResponsesProvider::Xai, "grok-4");
    let bad = ResponsesRequest {
        input: vec![PromptTurn {
            role: "tool".into(),
            text: "x".into(),
        }],
        max_output_tokens: 1,
        instructions: None,
    };
    assert_eq!(render_request(&p, &bad), Err(RenderError::Unsupported));
}

#[test]
fn prepare_requires_exact_revision_extension_and_pricing_binding() {
    use runne_provider::{ModelRef, ProviderCallId, ProviderCapability, ProviderId};
    let profile = ResponsesProfile::new(ResponsesProvider::Xai, "grok-4")
        .with_model_revision("2026-09-14")
        .with_binding_extension(serde_json::json!({"marker":"responses-effect"}))
        .with_pricing_revision_digest([3; 32]);
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([1; 16]),
        ModelRef::new(ProviderId::new("xai").unwrap(), "grok-4", "2026-09-14").unwrap(),
        [2; 32],
        64,
        serde_json::json!({"marker":"responses-effect"}),
    )
    .unwrap()
    .with_text_inputs(vec![
        runne_provider::ProviderTextInput::new(runne_provider::ProviderInputRole::User, "hello")
            .unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    assert!(prepare_call(&profile, &call).is_ok());

    let wrong_revision =
        ModelRef::new(ProviderId::new("xai").unwrap(), "grok-4", "changed").unwrap();
    let wrong_call = ProviderCall::new(
        call.call_id(),
        wrong_revision,
        [2; 32],
        64,
        call.extension().clone(),
    )
    .unwrap()
    .with_text_inputs(call.text_inputs().to_vec())
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    assert_eq!(
        prepare_call(&profile, &wrong_call),
        Err(RenderError::Unsupported)
    );

    let unbound = ResponsesProfile::new(ResponsesProvider::Xai, "grok-4");
    assert_eq!(prepare_call(&unbound, &call), Err(RenderError::Unsupported));
}

#[test]
fn codex_requires_the_attested_model_reservation_ceiling() {
    use crate::{CODEX_MAX_OUTPUT_TOKENS, CODEX_MODEL, PI_REFERENCE_REVISION};
    use runne_provider::{ModelRef, ProviderCallId, ProviderCapability, ProviderId};
    let profile = crate::codex_subscription_profile(CODEX_MAX_OUTPUT_TOKENS, [4; 32]);
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(
            ProviderId::new("openai-codex").unwrap(),
            CODEX_MODEL,
            PI_REFERENCE_REVISION,
        )
        .unwrap(),
        [5; 32],
        64,
        profile.effective_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        runne_provider::ProviderTextInput::new(runne_provider::ProviderInputRole::User, "hello")
            .unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    assert_eq!(prepare_call(&profile, &call), Err(RenderError::Unsupported));
}

#[test]
fn context_must_alternate_user_assistant_and_end_with_user() {
    let profile = ResponsesProfile::new(ResponsesProvider::Xai, "grok-4");
    let assistant_only = ResponsesRequest {
        input: vec![PromptTurn {
            role: "assistant".into(),
            text: "x".into(),
        }],
        max_output_tokens: 1,
        instructions: None,
    };
    assert_eq!(
        render_request(&profile, &assistant_only),
        Err(RenderError::Unsupported)
    );
    let user_assistant = ResponsesRequest {
        input: vec![
            PromptTurn {
                role: "user".into(),
                text: "x".into(),
            },
            PromptTurn {
                role: "assistant".into(),
                text: "y".into(),
            },
        ],
        max_output_tokens: 1,
        instructions: None,
    };
    assert_eq!(
        render_request(&profile, &user_assistant),
        Err(RenderError::Unsupported)
    );
}

#[test]
fn codex_omits_unsupported_output_limit_and_null_fields() {
    let profile = ResponsesProfile::new(ResponsesProvider::OpenAiCodex, "gpt-5.2");
    let body = render_request(
        &profile,
        &ResponsesRequest {
            input: vec![PromptTurn {
                role: "user".into(),
                text: "hello".into(),
            }],
            max_output_tokens: 32,
            instructions: None,
        },
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(value.get("max_output_tokens").is_none());
    assert!(value.get("instructions").is_none());
    assert!(value.get("tools").is_none());
}
