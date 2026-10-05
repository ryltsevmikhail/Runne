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
    tools: Vec<serde_json::Value>,
    tool_choice: String,
    background: bool,
    store: bool,
    stream: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    content: Vec<InputContent>,
    call_id: Option<String>,
    name: Option<String>,
    arguments: Option<String>,
    output: Option<String>,
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
        FixtureRequestKind::D2ToolProposal => valid_d2_inputs(&request.input),
        FixtureRequestKind::D2ToolLoopRound0 => valid_d2_loop_inputs(&request.input, 0),
        FixtureRequestKind::D2ToolLoopRound1 => valid_d2_loop_inputs(&request.input, 1),
        FixtureRequestKind::D2ToolLoopRound2 => valid_d2_loop_inputs(&request.input, 2),
        FixtureRequestKind::D2ToolLoop => false,
    };
    let expected_tools = ["workspace_file_read", "workspace_file_create_new"];
    let tools_valid = if is_tool_profile(kind) {
        request.tools.len() == 2
            && request
                .tools
                .iter()
                .zip(expected_tools)
                .all(|(tool, name)| {
                    tool["type"] == "function" && tool["name"] == name && tool["strict"] == true
                })
    } else {
        request.tools.is_empty()
    };
    request.model == "gpt-5.5-2026-04-23"
        && request.service_tier == "default"
        && request.max_output_tokens == 16_384
        && request.reasoning.effort == "none"
        && tools_valid
        && request.tool_choice
            == if is_tool_profile(kind) {
                "auto"
            } else {
                "none"
            }
        && !request.background
        && !request.store
        && request.stream
        && conversation
}

fn is_tool_profile(kind: FixtureRequestKind) -> bool {
    matches!(
        kind,
        FixtureRequestKind::D2ToolProposal
            | FixtureRequestKind::D2ToolLoopRound0
            | FixtureRequestKind::D2ToolLoopRound1
            | FixtureRequestKind::D2ToolLoopRound2
            | FixtureRequestKind::D2ToolLoop
    )
}

#[path = "body/d2_loop.rs"]
mod d2_loop;
use d2_loop::valid_d2_loop_inputs;

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
    (input.kind.is_empty() || input.kind == "message")
        && matches!(input.content.as_slice(), [content]
            if content.kind == expected_kind && content.text == expected)
}

#[path = "body/d2_proposal.rs"]
mod d2_proposal;
use d2_proposal::valid_d2_inputs;

#[cfg(test)]
#[path = "body/tests.rs"]
mod tests;
