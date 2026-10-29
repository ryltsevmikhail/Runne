use super::tool_render::DeepSeekToolRenderError;
use runne_provider::{ProviderCall, ProviderInputRole, ProviderToolResultV1};
use serde::Serialize;

pub fn render_inputs(
    call: &ProviderCall,
    max_entries: usize,
    max_entry_bytes: usize,
    input_limit: usize,
) -> Result<Vec<ToolInput<'_>>, DeepSeekToolRenderError> {
    let inputs = call.text_inputs();
    if inputs.is_empty() {
        return Err(DeepSeekToolRenderError::InvalidCommittedContext);
    }
    if inputs
        .len()
        .saturating_add(call.tool_results().len().saturating_mul(2))
        > max_entries
    {
        return Err(DeepSeekToolRenderError::ContextLimitExceeded);
    }
    let mut expected = ProviderInputRole::User;
    let mut total = 0usize;
    let mut rendered = Vec::with_capacity(inputs.len() + call.tool_results().len());
    for item in inputs {
        if item.role() != expected {
            return Err(DeepSeekToolRenderError::InvalidCommittedContext);
        }
        if item.text().len() > max_entry_bytes {
            return Err(DeepSeekToolRenderError::ContextLimitExceeded);
        }
        total = total
            .checked_add(item.text().len())
            .ok_or(DeepSeekToolRenderError::ContextLimitExceeded)?;
        if total > input_limit {
            return Err(DeepSeekToolRenderError::ContextLimitExceeded);
        }
        let (role, content_type) = match item.role() {
            ProviderInputRole::User => ("user", "input_text"),
            ProviderInputRole::Assistant => ("assistant", "output_text"),
            ProviderInputRole::Developer => {
                return Err(DeepSeekToolRenderError::InvalidCommittedContext);
            }
        };
        rendered.push(ToolInput::Message {
            role,
            content: [ToolContent {
                content_type,
                text: item.text(),
            }],
        });
        expected = match expected {
            ProviderInputRole::User => ProviderInputRole::Assistant,
            _ => ProviderInputRole::User,
        };
    }
    if inputs.last().map(runne_provider::ProviderTextInput::role) != Some(ProviderInputRole::User) {
        return Err(DeepSeekToolRenderError::InvalidCommittedContext);
    }
    for result in call.tool_results() {
        total = total
            .checked_add(result.arguments_json().len())
            .and_then(|bytes| bytes.checked_add(result.output().len()))
            .ok_or(DeepSeekToolRenderError::ContextLimitExceeded)?;
        if total > input_limit {
            return Err(DeepSeekToolRenderError::ContextLimitExceeded);
        }
    }
    rendered.extend(call.tool_results().iter().flat_map(|result| {
        [
            ToolInput::FunctionCall {
                call_id: result.call_id(),
                name: result.name().wire_name(),
                arguments: result.arguments_json(),
            },
            tool_output(result),
        ]
    }));
    Ok(rendered)
}

fn tool_output(result: &ProviderToolResultV1) -> ToolInput<'_> {
    ToolInput::FunctionCallOutput {
        call_id: result.call_id(),
        output: result.output(),
    }
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum ToolInput<'a> {
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
pub struct ToolContent<'a> {
    #[serde(rename = "type")]
    content_type: &'a str,
    text: &'a str,
}
