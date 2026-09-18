use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind, ProviderTerminalDisposition,
};
use runne_provider_chat_completions::{
    ChatCompletionsProfile, ChatCompletionsStreamDecoder, ChatCompletionsStreamError,
};

const fn profile(model: &'static str) -> ChatCompletionsProfile {
    ChatCompletionsProfile::new(
        "test-provider",
        "test-profile/1",
        model,
        "2026-09-14",
        "https://provider.example",
        "/compatible-mode/v1/chat/completions",
        [1; 32],
        [2; 32],
        4,
        100,
        400,
        100,
        1024,
        512,
    )
}

fn decode(wire: &str) -> Result<Vec<ProviderStreamEvent>, ChatCompletionsStreamError> {
    let mut decoder = ChatCompletionsStreamDecoder::default();
    decoder.push(wire.as_bytes())?;
    decoder.finish()
}

#[test]
fn accepts_zai_profile_fixture_with_stable_identity() {
    let wire = concat!(
        "data: {\"id\":\"zai-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"glm-5.2\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning_content\":\"hidden\",\"content\":\"Привет\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"zai-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"glm-5.2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"!\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"id\":\"zai-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"glm-5.2\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":3,\"total_tokens\":13,\"prompt_tokens_details\":{\"cached_tokens\":2},\"completion_tokens_details\":{\"reasoning_tokens\":1}}}\n\n",
        "data: [DONE]\n\n"
    );
    let mut decoder = ChatCompletionsStreamDecoder::for_profile(&profile("glm-5.2"));
    for byte in wire.bytes() {
        decoder.push(&[byte]).expect("fragment");
    }
    let events = decoder.finish().expect("Z.ai fixture is valid");
    assert!(matches!(events[0].kind(), ProviderStreamEventKind::Started));
    let text = events
        .iter()
        .filter_map(|event| match event.kind() {
            ProviderStreamEventKind::TextDelta { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<String>();
    assert_eq!(text, "Привет!");
    let usage = events
        .iter()
        .find_map(|event| match event.kind() {
            ProviderStreamEventKind::Usage { usage } => Some(*usage),
            _ => None,
        })
        .expect("usage");
    assert_eq!(usage.input_tokens(), 10);
    assert_eq!(usage.cached_input_tokens(), 2);
    assert_eq!(usage.reasoning_output_tokens(), 1);
}

#[test]
fn accepts_qwen_profile_fixture_with_stable_identity() {
    let wire = concat!(
        "data: {\"id\":\"qwen-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen3.8-max\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Qwen\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"qwen-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen3.8-max\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" text\"},\"finish_reason\":\"length\"}]}\n\n",
        "data: {\"id\":\"qwen-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen3.8-max\",\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n",
        "data: [DONE]\n\n"
    );
    let events = {
        let mut decoder = ChatCompletionsStreamDecoder::for_profile(&profile("qwen3.8-max"));
        decoder.push(wire.as_bytes()).expect("Qwen fixture");
        decoder.finish().expect("Qwen fixture is valid")
    };
    assert!(matches!(
        events.last().map(ProviderStreamEvent::kind),
        Some(ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteIncomplete,
            reason: ProviderFinishReason::Length
        })
    ));
}

#[test]
fn rejects_response_identity_changes_against_exact_profile() {
    let changed_model = "data: {\"id\":\"same\",\"model\":\"wrong-model\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n";
    let mut decoder = ChatCompletionsStreamDecoder::for_profile(&profile("glm-5.2"));
    assert_eq!(
        decoder.push(changed_model.as_bytes()),
        Err(ChatCompletionsStreamError::Malformed)
    );

    let first = "data: {\"id\":\"first\",\"model\":\"glm-5.2\",\"choices\":[{\"delta\":{},\"finish_reason\":null}]}\n\n";
    let second = "data: {\"id\":\"second\",\"model\":\"glm-5.2\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n";
    let mut decoder = ChatCompletionsStreamDecoder::for_profile(&profile("glm-5.2"));
    decoder.push(first.as_bytes()).expect("first frame");
    assert_eq!(
        decoder.push(second.as_bytes()),
        Err(ChatCompletionsStreamError::Malformed)
    );
}

#[test]
fn requires_finish_reason_before_done_and_rejects_events_after_done() {
    let missing_reason = "data: {\"choices\":[]}\n\ndata: [DONE]\n\n";
    assert_eq!(
        decode(missing_reason),
        Err(ChatCompletionsStreamError::Malformed)
    );

    let after_done = concat!(
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n",
        "data: {\"choices\":[]}\n\n"
    );
    assert_eq!(
        decode(after_done),
        Err(ChatCompletionsStreamError::Malformed)
    );
}

#[test]
fn rejects_duplicate_usage_and_inconsistent_total() {
    let duplicate = concat!(
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n"
    );
    assert_eq!(
        decode(duplicate),
        Err(ChatCompletionsStreamError::InvalidUsage)
    );

    let inconsistent = concat!(
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":99}}\n\n",
        "data: [DONE]\n\n"
    );
    assert_eq!(
        decode(inconsistent),
        Err(ChatCompletionsStreamError::InvalidUsage)
    );
}

#[test]
fn rejects_tool_calls_and_truncated_sse_frames() {
    let tool_call = concat!(
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"call_1\"}]},\"finish_reason\":null}]}\n\n",
        "data: [DONE]\n\n"
    );
    assert_eq!(
        decode(tool_call),
        Err(ChatCompletionsStreamError::Malformed)
    );

    let truncated =
        "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n";
    assert_eq!(
        decode(truncated),
        Err(ChatCompletionsStreamError::TerminalMissing)
    );
}

#[test]
fn profile_response_frame_bound_is_enforced() {
    let wire = format!("data: {}\n\n", "x".repeat(513));
    let mut decoder = ChatCompletionsStreamDecoder::for_profile(&profile("glm-5.2"));
    assert_eq!(
        decoder.push(wire.as_bytes()),
        Err(ChatCompletionsStreamError::BoundExceeded)
    );
}
