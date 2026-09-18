use crate::ResponsesProfile;
use runne_provider::{
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderCapability, ProviderInputRole,
};
use serde_json::{Value, json};
use thiserror::Error;

/// One text turn in a Responses request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptTurn {
    /// Conversation role.
    pub role: String,
    /// Text content.
    pub text: String,
}

/// Credential-free bounded Responses request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsesRequest {
    /// Ordered text turns.
    pub input: Vec<PromptTurn>,
    /// Output token ceiling.
    pub max_output_tokens: u32,
    /// Optional instruction string.
    pub instructions: Option<String>,
}

/// Request rendering failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RenderError {
    /// A request field violated a bound.
    #[error("responses request is outside bounds")]
    Bound,
    /// A role, capability or profile binding is unsupported.
    #[error("responses request is not text-only or profile-bound")]
    Unsupported,
}

/// Renders a canonical call and seals its bytes in Runne's prepared-request contract.
pub fn prepare_call(
    profile: &ResponsesProfile,
    call: &ProviderCall,
) -> Result<PreparedRequest, RenderError> {
    if profile.model_revision().is_empty()
        || profile.pricing_revision_digest() == [0; 32]
        || call.model_ref().provider_id().as_str() != profile.provider_id()
        || call.model_ref().model_id() != profile.model()
        || call.model_ref().revision() != profile.model_revision()
        || call.extension() != &profile.effective_binding_extension()
        || call.required_capabilities() != [ProviderCapability::Streaming]
        || (profile.provider() == crate::ResponsesProvider::OpenAiCodex
            && call.max_output_tokens() != profile.max_output_tokens())
    {
        return Err(RenderError::Unsupported);
    }
    let input = call
        .text_inputs()
        .iter()
        .map(|turn| PromptTurn {
            role: match turn.role() {
                ProviderInputRole::Developer => "developer",
                ProviderInputRole::User => "user",
                ProviderInputRole::Assistant => "assistant",
            }
            .into(),
            text: turn.text().to_owned(),
        })
        .collect();
    let body = render_request(
        profile,
        &ResponsesRequest {
            input,
            max_output_tokens: call.max_output_tokens(),
            instructions: None,
        },
    )?;
    PreparedRequest::from_rendered_call_for_digest_version(
        call,
        ProviderCallDigestVersion::V2,
        body,
    )
    .map_err(|_| RenderError::Bound)
}

/// Renders exact text-only Responses JSON with subscription-safe defaults.
pub fn render_request(
    profile: &ResponsesProfile,
    request: &ResponsesRequest,
) -> Result<Vec<u8>, RenderError> {
    if request.max_output_tokens == 0 || request.max_output_tokens > profile.max_output_tokens() {
        return Err(RenderError::Bound);
    }
    if request.input.is_empty() || request.input.len() > profile.max_input_entries() {
        return Err(RenderError::Bound);
    }
    let mut expected_role = "user";
    let mut total_bytes = 0usize;
    for turn in &request.input {
        if turn.role != expected_role
            || turn.text.is_empty()
            || turn.text.len() > profile.max_input_entry_bytes()
        {
            return Err(RenderError::Unsupported);
        }
        total_bytes = total_bytes
            .checked_add(turn.text.len())
            .ok_or(RenderError::Bound)?;
        if total_bytes > profile.max_input_bytes() {
            return Err(RenderError::Bound);
        }
        expected_role = if expected_role == "user" {
            "assistant"
        } else {
            "user"
        };
    }
    if expected_role != "assistant" {
        return Err(RenderError::Unsupported);
    }
    if request
        .instructions
        .as_ref()
        .is_some_and(|v| v.len() > profile.max_input_entry_bytes())
    {
        return Err(RenderError::Bound);
    }
    let input: Vec<Value> = request.input.iter().map(|turn| json!({"role": turn.role, "content": [{"type": if turn.role == "assistant" { "output_text" } else { "input_text" }, "text": turn.text}]})).collect();
    let mut body =
        json!({"model": profile.request_model(), "store": false, "stream": true, "input": input});
    if profile.provider() != crate::ResponsesProvider::OpenAiCodex {
        body["max_output_tokens"] = json!(request.max_output_tokens);
    }
    if let Some(instructions) = &request.instructions {
        body["instructions"] = json!(instructions);
    }
    let body = serde_json::to_vec(&body).map_err(|_| RenderError::Bound)?;
    if body.len() > profile.max_request_bytes() {
        return Err(RenderError::Bound);
    }
    Ok(body)
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod tests;
