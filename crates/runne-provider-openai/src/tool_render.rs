use runne_provider::{
    PrepareError, PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderCapability,
    ProviderInputRole, ProviderToolNameV1, ProviderToolResultV1, TextProviderProfile,
    ToolProviderProfile,
};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::OpenAiResponsesToolProfile;

/// Deterministic rendering failure for the explicit workspace tool profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OpenAiToolRenderError {
    /// Call identity/profile binding, capability or fixed schema differed.
    #[error("provider call does not match the exact OpenAI tool profile")]
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
pub struct OpenAiResponsesToolRenderer {
    profile: OpenAiResponsesToolProfile,
}

impl OpenAiResponsesToolRenderer {
    /// Binds rendering to one validated opt-in profile.
    #[must_use]
    pub const fn new(profile: OpenAiResponsesToolProfile) -> Self {
        Self { profile }
    }

    /// Validates all call fields and builds the exact credential-free request.
    ///
    /// # Errors
    ///
    /// Returns an error when the call identity, context, bounds, declarations, or result
    /// correlation do not satisfy the opt-in profile.
    pub fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, OpenAiToolRenderError> {
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
                description: description(declaration.name()),
                parameters: declaration.parameters(),
                strict: true,
            })
            .collect();
        let request = ToolResponsesRequest {
            model: self.profile.text_profile().request_model(),
            service_tier: self.profile.text_profile().service_tier(),
            input,
            max_output_tokens: call.max_output_tokens(),
            reasoning: Reasoning { effort: "none" },
            tools,
            tool_choice: "auto",
            background: false,
            store: false,
            stream: true,
        };
        let mut bytes =
            serde_json::to_vec(&request).map_err(|_| OpenAiToolRenderError::RenderFailure)?;
        bytes.push(b'\n');
        if bytes.len() > self.profile.max_request_bytes() {
            return Err(OpenAiToolRenderError::ContextLimitExceeded);
        }
        PreparedRequest::from_rendered_call_for_digest_version(
            call,
            ProviderCallDigestVersion::V2,
            bytes,
        )
        .map_err(|error| map_prepare_error(&error))
    }

    fn validate_call(&self, call: &ProviderCall) -> Result<(), OpenAiToolRenderError> {
        let profile = self.profile.text_profile();
        if call.model_ref().provider_id().as_str() != profile.provider_id()
            || call.model_ref().model_id() != profile.model_id()
            || call.model_ref().revision() != profile.model_revision()
            || call.max_output_tokens() > self.profile.max_output_tokens()
            || call.required_capabilities()
                != [ProviderCapability::Streaming, ProviderCapability::Tools]
        {
            return Err(OpenAiToolRenderError::ProfileBindingMismatch);
        }
        if call.tool_declarations() != self.profile.tool_declarations() {
            return Err(OpenAiToolRenderError::UnsupportedToolContext);
        }
        if call.tool_results().iter().any(|result| {
            !self
                .profile
                .tool_declarations()
                .iter()
                .any(|d| d.name() == result.name())
        }) {
            return Err(OpenAiToolRenderError::UnsupportedToolContext);
        }
        validate_extension(call.extension(), &self.profile)
    }
}

fn render_inputs(
    call: &ProviderCall,
    max_entries: usize,
    max_entry_bytes: usize,
    input_limit: usize,
) -> Result<Vec<ToolInput<'_>>, OpenAiToolRenderError> {
    let inputs = call.text_inputs();
    if inputs.is_empty() {
        return Err(OpenAiToolRenderError::InvalidCommittedContext);
    }
    if inputs.len() > max_entries {
        return Err(OpenAiToolRenderError::ContextLimitExceeded);
    }
    let mut expected = ProviderInputRole::User;
    let mut total = 0usize;
    let mut rendered = Vec::with_capacity(inputs.len() + call.tool_results().len());
    for item in inputs {
        if item.role() != expected {
            return Err(OpenAiToolRenderError::InvalidCommittedContext);
        }
        if item.text().len() > max_entry_bytes {
            return Err(OpenAiToolRenderError::ContextLimitExceeded);
        }
        total = total
            .checked_add(item.text().len())
            .ok_or(OpenAiToolRenderError::ContextLimitExceeded)?;
        if total > input_limit {
            return Err(OpenAiToolRenderError::ContextLimitExceeded);
        }
        let (role, content_type) = match item.role() {
            ProviderInputRole::User => ("user", "input_text"),
            ProviderInputRole::Assistant => ("assistant", "output_text"),
            ProviderInputRole::Developer => {
                return Err(OpenAiToolRenderError::InvalidCommittedContext);
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
        return Err(OpenAiToolRenderError::InvalidCommittedContext);
    }
    for result in call.tool_results() {
        total = total
            .checked_add(result.arguments_json().len())
            .and_then(|bytes| bytes.checked_add(result.output().len()))
            .ok_or(OpenAiToolRenderError::ContextLimitExceeded)?;
        if total > input_limit {
            return Err(OpenAiToolRenderError::ContextLimitExceeded);
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

fn validate_extension(
    value: &Value,
    profile: &OpenAiResponsesToolProfile,
) -> Result<(), OpenAiToolRenderError> {
    let object = value
        .as_object()
        .ok_or(OpenAiToolRenderError::ProfileBindingMismatch)?;
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
        return Err(OpenAiToolRenderError::ProfileBindingMismatch);
    }
    Ok(())
}

const fn description(name: ProviderToolNameV1) -> &'static str {
    match name {
        ProviderToolNameV1::WorkspaceFileRead => {
            "Read a bounded regular file within the approved workspace."
        }
        ProviderToolNameV1::WorkspaceFileCreateNew => {
            "Create a new file within the approved workspace; fails if it already exists."
        }
    }
}

const fn map_prepare_error(error: &PrepareError) -> OpenAiToolRenderError {
    match error {
        PrepareError::RenderedRequestBound => OpenAiToolRenderError::ContextLimitExceeded,
        _ => OpenAiToolRenderError::RenderFailure,
    }
}

#[derive(Serialize)]
struct ToolResponsesRequest<'a> {
    model: &'a str,
    service_tier: &'a str,
    input: Vec<ToolInput<'a>>,
    max_output_tokens: u32,
    reasoning: Reasoning<'a>,
    tools: Vec<ToolDefinition<'a>>,
    tool_choice: &'a str,
    background: bool,
    store: bool,
    stream: bool,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ToolInput<'a> {
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
struct ToolContent<'a> {
    #[serde(rename = "type")]
    content_type: &'a str,
    text: &'a str,
}

#[derive(Serialize)]
struct ToolDefinition<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    name: &'a str,
    description: &'a str,
    parameters: &'a Value,
    strict: bool,
}

#[derive(Serialize)]
struct Reasoning<'a> {
    effort: &'a str,
}
