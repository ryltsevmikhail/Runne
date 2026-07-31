use gocode_provider::{
    PrepareError, PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderCapability,
    ProviderInputRole,
};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::OpenAiResponsesTextProfile;

/// Deterministic `OpenAI` Responses request rendering failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OpenAiRenderError {
    /// Provider/model/profile/pricing binding differs from the exact profile.
    #[error("provider call does not match the exact OpenAI profile")]
    ProfileBindingMismatch,
    /// Required capabilities are not exactly the text-streaming profile.
    #[error("provider call requires an unsupported capability")]
    UnsupportedCapability,
    /// Provider-specific extension contains an unrecognized or changed field.
    #[error("provider call extension is forbidden")]
    ForbiddenExtension,
    /// Committed Conversation context has no current user message.
    #[error("committed Conversation context is empty")]
    EmptyCommittedContext,
    /// Committed user/assistant role ordering is not canonical.
    #[error("committed Conversation context role sequence is invalid")]
    InvalidCommittedContext,
    /// A runtime-owned developer prompt is forbidden by this profile.
    #[error("developer prompt is forbidden by this profile")]
    DeveloperPromptForbidden,
    /// Context, output or serialized request exceeded an exact profile bound.
    #[error("provider request exceeds the exact profile bound")]
    ContextLimitExceeded,
    /// Credential-free request serialization or preparation failed.
    #[error("provider request rendering failed")]
    RenderFailure,
}

/// Deterministic renderer bound to one validated immutable profile.
#[derive(Debug, Clone)]
pub struct OpenAiResponsesTextRenderer {
    profile: OpenAiResponsesTextProfile,
}

impl OpenAiResponsesTextRenderer {
    /// Binds rendering to one already validated profile.
    #[must_use]
    pub const fn new(profile: OpenAiResponsesTextProfile) -> Self {
        Self { profile }
    }

    /// Validates canonical committed context and builds exact credential-free bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed [`OpenAiRenderError`] when the provider call differs
    /// from the exact profile or exceeds a profile bound.
    pub fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, OpenAiRenderError> {
        self.validate_call_binding(call)?;
        let input = self.render_inputs(call)?;
        let request = ResponsesRequest {
            model: self.profile.request_model(),
            input,
            max_output_tokens: call.max_output_tokens(),
            reasoning: Reasoning { effort: "none" },
            tools: Vec::new(),
            tool_choice: "none",
            background: false,
            store: false,
            stream: true,
        };
        let mut bytes =
            serde_json::to_vec(&request).map_err(|_| OpenAiRenderError::RenderFailure)?;
        bytes.push(b'\n');
        if bytes.len() > self.profile.max_request_bytes() {
            return Err(OpenAiRenderError::ContextLimitExceeded);
        }
        PreparedRequest::from_rendered_call_for_digest_version(
            call,
            ProviderCallDigestVersion::V2,
            bytes,
        )
        .map_err(|error| map_prepare_error(&error))
    }

    fn validate_call_binding(&self, call: &ProviderCall) -> Result<(), OpenAiRenderError> {
        if call.model_ref().provider_id().as_str() != self.profile.provider_id()
            || call.model_ref().model_id() != self.profile.model_id()
            || call.model_ref().revision() != self.profile.model_revision()
        {
            return Err(OpenAiRenderError::ProfileBindingMismatch);
        }
        if call.required_capabilities() != [ProviderCapability::Streaming] {
            return Err(OpenAiRenderError::UnsupportedCapability);
        }
        validate_extension(call.extension(), &self.profile)?;
        if call.max_output_tokens() > self.profile.max_output_tokens() {
            return Err(OpenAiRenderError::ContextLimitExceeded);
        }
        Ok(())
    }

    fn render_inputs<'a>(
        &self,
        call: &'a ProviderCall,
    ) -> Result<Vec<ResponsesInput<'a>>, OpenAiRenderError> {
        let inputs = call.text_inputs();
        if inputs.is_empty() {
            return Err(OpenAiRenderError::EmptyCommittedContext);
        }
        if inputs.len() > self.profile.max_input_entries() {
            return Err(OpenAiRenderError::ContextLimitExceeded);
        }
        let mut aggregate_bytes = 0usize;
        let mut expected = ProviderInputRole::User;
        let mut rendered = Vec::with_capacity(inputs.len());
        for input in inputs {
            if input.role() == ProviderInputRole::Developer {
                return Err(OpenAiRenderError::DeveloperPromptForbidden);
            }
            if input.role() != expected {
                return Err(OpenAiRenderError::InvalidCommittedContext);
            }
            if input.text().len() > self.profile.max_input_entry_bytes() {
                return Err(OpenAiRenderError::ContextLimitExceeded);
            }
            aggregate_bytes = aggregate_bytes
                .checked_add(input.text().len())
                .ok_or(OpenAiRenderError::ContextLimitExceeded)?;
            if aggregate_bytes > self.profile.max_input_bytes() {
                return Err(OpenAiRenderError::ContextLimitExceeded);
            }
            let (role, content_type) = match input.role() {
                ProviderInputRole::User => ("user", "input_text"),
                ProviderInputRole::Assistant => ("assistant", "output_text"),
                ProviderInputRole::Developer => unreachable!("rejected above"),
            };
            rendered.push(ResponsesInput {
                role,
                content: [ResponsesContent {
                    content_type,
                    text: input.text(),
                }],
            });
            expected = match expected {
                ProviderInputRole::User => ProviderInputRole::Assistant,
                ProviderInputRole::Assistant => ProviderInputRole::User,
                ProviderInputRole::Developer => unreachable!("never expected"),
            };
        }
        if inputs.last().map(gocode_provider::ProviderTextInput::role)
            != Some(ProviderInputRole::User)
        {
            return Err(OpenAiRenderError::InvalidCommittedContext);
        }
        Ok(rendered)
    }
}

fn validate_extension(
    extension: &Value,
    profile: &OpenAiResponsesTextProfile,
) -> Result<(), OpenAiRenderError> {
    let object = extension
        .as_object()
        .ok_or(OpenAiRenderError::ForbiddenExtension)?;
    if object.len() != 3
        || object.get("profile_id").and_then(Value::as_str) != Some(profile.profile_id())
        || object.get("profile_digest").and_then(Value::as_str)
            != Some(hex::encode(profile.profile_digest()).as_str())
        || object
            .get("pricing_revision_digest")
            .and_then(Value::as_str)
            != Some(hex::encode(profile.pricing_revision_digest()).as_str())
    {
        return Err(OpenAiRenderError::ForbiddenExtension);
    }
    Ok(())
}

const fn map_prepare_error(error: &PrepareError) -> OpenAiRenderError {
    match error {
        PrepareError::RenderedRequestBound => OpenAiRenderError::ContextLimitExceeded,
        PrepareError::UnsupportedCapability(_)
        | PrepareError::Render(_)
        | PrepareError::UnsupportedDigestVersion(_) => OpenAiRenderError::RenderFailure,
    }
}

#[derive(Serialize)]
struct ResponsesRequest<'a> {
    model: &'a str,
    input: Vec<ResponsesInput<'a>>,
    max_output_tokens: u32,
    reasoning: Reasoning<'a>,
    tools: Vec<Value>,
    tool_choice: &'a str,
    background: bool,
    store: bool,
    stream: bool,
}

#[derive(Serialize)]
struct ResponsesInput<'a> {
    role: &'a str,
    content: [ResponsesContent<'a>; 1],
}

#[derive(Serialize)]
struct ResponsesContent<'a> {
    #[serde(rename = "type")]
    content_type: &'a str,
    text: &'a str,
}

#[derive(Serialize)]
struct Reasoning<'a> {
    effort: &'a str,
}
