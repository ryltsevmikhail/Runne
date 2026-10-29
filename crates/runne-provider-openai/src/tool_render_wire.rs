use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
pub(super) struct ToolResponsesRequest<'a> {
    pub(super) model: &'a str,
    pub(super) service_tier: &'a str,
    pub(super) input: Vec<ToolInput<'a>>,
    pub(super) max_output_tokens: u32,
    pub(super) reasoning: Reasoning<'a>,
    pub(super) tools: Vec<ToolDefinition<'a>>,
    pub(super) tool_choice: &'a str,
    pub(super) background: bool,
    pub(super) store: bool,
    pub(super) stream: bool,
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub(super) enum ToolInput<'a> {
    #[serde(rename = "message")]
    Message {
        role: &'a str,
        content: [ToolContent<'a>; 1],
    },
    #[serde(rename = "function_call")]
    FunctionCall {
        call_id: &'a str,
        name: &'a str,
        arguments: &'a str,
    },
    #[serde(rename = "function_call_output")]
    FunctionCallOutput { call_id: &'a str, output: &'a str },
}

#[derive(Serialize)]
pub(super) struct ToolContent<'a> {
    #[serde(rename = "type")]
    pub(super) content_type: &'a str,
    pub(super) text: &'a str,
}

#[derive(Serialize)]
pub(super) struct ToolDefinition<'a> {
    #[serde(rename = "type")]
    pub(super) kind: &'a str,
    pub(super) name: &'a str,
    pub(super) description: &'a str,
    pub(super) parameters: &'a Value,
    pub(super) strict: bool,
}

#[derive(Serialize)]
pub(super) struct Reasoning<'a> {
    pub(super) effort: &'a str,
}
