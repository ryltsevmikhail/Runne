use runne_provider::{
    PrepareError, PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderCapability,
    TextProviderProfile, ToolProviderProfile,
};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use super::tool_inputs::{ToolInput, render_inputs};
use crate::DeepSeekResponsesToolProfile;

/// Deterministic rendering failure for the explicit workspace tool profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DeepSeekToolRenderError {
    /// Call identity/profile binding, capability or fixed schema differed.
    #[error("provider call does not match the exact DeepSeek tool profile")]
    ProfileBindingMismatch,
    /// Tool capability, declaration, or result correlation is unsupported.
    #[error("provider call has unsupported tool context")]
    UnsupportedToolContext,
    /// Committed conversation is empty or its role sequence is invalid.
    #[error("committed Conversation context is invalid")]
    InvalidCommittedContext,
    /// A request bound was exceeded.
    #[error("provider request exceeds the exact profile bound")]
    ContextLimitExceeded,
    /// Credential-free serialization or preparation failed.
    #[error("provider request rendering failed")]
    RenderFailure,
}

/// Renderer bound to the fixed opt-in workspace tool profile.
#[derive(Debug, Clone)]
pub struct DeepSeekResponsesToolRenderer {
    profile: DeepSeekResponsesToolProfile,
}

impl DeepSeekResponsesToolRenderer {
    /// Binds rendering to one validated opt-in profile.
    #[must_use]
    pub const fn new(profile: DeepSeekResponsesToolProfile) -> Self {
        Self { profile }
    }

    /// Validates all call fields and builds the exact credential-free request.
    ///
    /// # Errors
    ///
    /// Returns an error when the call identity, context, bounds, declarations, or result
    /// correlation do not satisfy the opt-in profile.
    pub fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, DeepSeekToolRenderError> {
        self.validate_call(call)?;
        let input = render_inputs(
            call,
            self.profile.max_input_entries(),
            self.profile.max_input_entry_bytes(),
            self.profile.max_input_bytes(),
        )?;
        let tools = self
            .profile
            .tool_declarations()
            .iter()
            .map(|declaration| ToolDefinition {
                kind: "function",
                name: declaration.name().wire_name(),
                description: "Runtime-approved bounded workspace operation.",
                parameters: declaration.parameters(),
            })
            .collect();
        let request = ToolResponsesRequest {
            model: self.profile.text_profile().request_model(),
            input,
            instructions: super::tool_profile::TOOL_INSTRUCTIONS,
            max_output_tokens: call.max_output_tokens(),
            reasoning: Reasoning { effort: "none" },
            tools,
            tool_choice: "auto",
            stream: true,
        };
        let mut bytes =
            serde_json::to_vec(&request).map_err(|_| DeepSeekToolRenderError::RenderFailure)?;
        bytes.push(b'\n');
        if bytes.len() > self.profile.max_request_bytes() {
            return Err(DeepSeekToolRenderError::ContextLimitExceeded);
        }
        PreparedRequest::from_rendered_call_for_digest_version(
            call,
            ProviderCallDigestVersion::V2,
            bytes,
        )
        .map_err(|error| map_prepare_error(&error))
    }

    fn validate_call(&self, call: &ProviderCall) -> Result<(), DeepSeekToolRenderError> {
        let profile = self.profile.text_profile();
        if call.model_ref().provider_id().as_str() != profile.provider_id()
            || call.model_ref().model_id() != profile.model_id()
            || call.model_ref().revision() != profile.model_revision()
            || call.max_output_tokens() > self.profile.max_output_tokens()
            || call.required_capabilities()
                != [ProviderCapability::Streaming, ProviderCapability::Tools]
        {
            return Err(DeepSeekToolRenderError::ProfileBindingMismatch);
        }
        if call.tool_declarations() != self.profile.tool_declarations() {
            return Err(DeepSeekToolRenderError::UnsupportedToolContext);
        }
        if call.tool_results().iter().any(|result| {
            !self
                .profile
                .tool_declarations()
                .iter()
                .any(|d| d.name() == result.name())
        }) {
            return Err(DeepSeekToolRenderError::UnsupportedToolContext);
        }
        validate_extension(call.extension(), &self.profile)
    }
}

fn validate_extension(
    value: &Value,
    profile: &DeepSeekResponsesToolProfile,
) -> Result<(), DeepSeekToolRenderError> {
    let object = value
        .as_object()
        .ok_or(DeepSeekToolRenderError::ProfileBindingMismatch)?;
    if object.len() != 4
        || object.get("profile_id").and_then(Value::as_str) != Some(profile.profile_id())
        || object.get("profile_digest").and_then(Value::as_str)
            != Some(hex::encode(profile.profile_digest()).as_str())
        || object
            .get("pricing_revision_digest")
            .and_then(Value::as_str)
            != Some(hex::encode(profile.pricing_revision_digest()).as_str())
        || object.get("tool_schema_digest").and_then(Value::as_str)
            != Some(hex::encode(profile.tool_schema_digest()).as_str())
    {
        return Err(DeepSeekToolRenderError::ProfileBindingMismatch);
    }
    Ok(())
}

const fn map_prepare_error(error: &PrepareError) -> DeepSeekToolRenderError {
    match error {
        PrepareError::RenderedRequestBound => DeepSeekToolRenderError::ContextLimitExceeded,
        _ => DeepSeekToolRenderError::RenderFailure,
    }
}

#[derive(Serialize)]
struct ToolResponsesRequest<'a> {
    model: &'a str,
    input: Vec<ToolInput<'a>>,
    instructions: &'a str,
    max_output_tokens: u32,
    reasoning: Reasoning<'a>,
    tools: Vec<ToolDefinition<'a>>,
    tool_choice: &'a str,
    stream: bool,
}

#[derive(Serialize)]
struct ToolDefinition<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    name: &'a str,
    description: &'a str,
    parameters: &'a Value,
}

#[derive(Serialize)]
struct Reasoning<'a> {
    effort: &'a str,
}
