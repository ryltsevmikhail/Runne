use runne_provider::ProviderCall;
use serde::Serialize;

use super::{anthropic, common::ProfileView};
use crate::GeminiRenderError;

#[derive(Serialize)]
pub(crate) struct Request<'a> {
    pub(crate) contents: Vec<Content<'a>>,
    #[serde(rename = "generationConfig")]
    pub(crate) generation_config: GenerationConfig,
}

#[derive(Serialize)]
pub(crate) struct Content<'a> {
    pub(crate) role: &'a str,
    pub(crate) parts: Vec<Part<'a>>,
}

#[derive(Serialize)]
pub(crate) struct Part<'a> {
    pub(crate) text: &'a str,
}

#[derive(Serialize)]
pub(crate) struct GenerationConfig {
    #[serde(rename = "maxOutputTokens")]
    pub(crate) max_output_tokens: u32,
}

pub(crate) fn render_contents<'a, P: ProfileView>(
    call: &'a ProviderCall,
    profile: &P,
    invalid: GeminiRenderError,
    bound: GeminiRenderError,
) -> Result<Vec<Content<'a>>, GeminiRenderError> {
    let messages = anthropic::render_messages(
        call,
        profile,
        AnthropicRenderError::InvalidContext,
        AnthropicRenderError::BoundExceeded,
    )
    .map_err(|error| match error {
        AnthropicRenderError::InvalidContext => invalid,
        _ => bound,
    })?;
    Ok(messages
        .into_iter()
        .map(|message| Content {
            role: if message.role == "assistant" {
                "model"
            } else {
                "user"
            },
            parts: vec![Part {
                text: message.content,
            }],
        })
        .collect())
}

use crate::AnthropicRenderError;
