use runne_provider::{ProviderCall, ProviderInputRole, ProviderTextInput};
use serde::Serialize;

use super::common::ProfileView;
use crate::AnthropicRenderError;

#[derive(Serialize)]
pub struct Request<'a> {
    pub(crate) model: &'a str,
    pub(crate) max_tokens: u32,
    pub(crate) messages: Vec<Message<'a>>,
    pub(crate) stream: bool,
}

#[derive(Serialize)]
pub struct Message<'a> {
    pub(crate) role: &'a str,
    pub(crate) content: &'a str,
}

pub fn render_messages<'a, P: ProfileView>(
    call: &'a ProviderCall,
    profile: &P,
    invalid: AnthropicRenderError,
    bound: AnthropicRenderError,
) -> Result<Vec<Message<'a>>, AnthropicRenderError> {
    let inputs = call.text_inputs();
    if inputs.is_empty() || inputs.len() > profile.limits().max_input_entries() {
        return Err(if inputs.is_empty() { invalid } else { bound });
    }
    let mut expected = ProviderInputRole::User;
    let mut total = 0usize;
    let mut output = Vec::with_capacity(inputs.len());
    for input in inputs {
        if input.role() != expected || input.role() == ProviderInputRole::Developer {
            return Err(invalid);
        }
        if input.text().len() > profile.limits().max_input_entry_bytes() {
            return Err(bound);
        }
        total = total
            .checked_add(input.text().len())
            .filter(|value| *value <= profile.limits().max_input_bytes())
            .ok_or(bound)?;
        output.push(Message {
            role: match input.role() {
                ProviderInputRole::User => "user",
                ProviderInputRole::Assistant => "assistant",
                ProviderInputRole::Developer => unreachable!(),
            },
            content: input.text(),
        });
        expected = match expected {
            ProviderInputRole::User => ProviderInputRole::Assistant,
            ProviderInputRole::Assistant => ProviderInputRole::User,
            ProviderInputRole::Developer => unreachable!(),
        };
    }
    if inputs.last().map(ProviderTextInput::role) != Some(ProviderInputRole::User) {
        return Err(invalid);
    }
    Ok(output)
}
