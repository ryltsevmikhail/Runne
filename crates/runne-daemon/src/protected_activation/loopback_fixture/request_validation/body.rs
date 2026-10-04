use super::FixtureRequestKind;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    model: String,
    service_tier: String,
    input: Vec<Input>,
    max_output_tokens: u64,
    reasoning: Reasoning,
    tools: Vec<serde::de::IgnoredAny>,
    tool_choice: String,
    background: bool,
    store: bool,
    stream: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    role: String,
    content: Vec<InputContent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputContent {
    #[serde(rename = "type")]
    kind: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reasoning {
    effort: String,
}

pub(super) fn matches_expected_body(request: Request, kind: FixtureRequestKind) -> bool {
    let single_prompt = matches!(request.input.as_slice(), [input]
        if input.role == "user" && input_text(input, "input_text", "fixture input"));
    let conversation = match kind {
        FixtureRequestKind::Pinned => single_prompt,
        FixtureRequestKind::ServicePointOfUse => valid_fixture_conversation(&request.input),
    };
    request.model == "gpt-5.5-2026-04-23"
        && request.service_tier == "default"
        && request.max_output_tokens == 16_384
        && request.reasoning.effort == "none"
        && request.tools.is_empty()
        && request.tool_choice == "none"
        && !request.background
        && !request.store
        && request.stream
        && conversation
}

fn valid_fixture_conversation(input: &[Input]) -> bool {
    matches!(input.len(), 1 | 3 | 5)
        && input.iter().enumerate().all(|(index, message)| {
            if index % 2 == 0 {
                message.role == "user" && input_text(message, "input_text", "fixture input")
            } else {
                message.role == "assistant"
                    && input_text(message, "output_text", "fixture response")
            }
        })
}

fn input_text(input: &Input, expected_kind: &str, expected: &str) -> bool {
    matches!(input.content.as_slice(), [content]
        if content.kind == expected_kind && content.text == expected)
}
