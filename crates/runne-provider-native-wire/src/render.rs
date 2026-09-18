mod anthropic;
mod common;
mod gemini;

use runne_provider::{PreparedRequest, ProviderCall};
use serde_json::Value;
use thiserror::Error;

use crate::{AnthropicMessagesProfile, GeminiProfile};

/// Anthropic request rendering failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AnthropicRenderError {
    /// Provider, model or revision differs from the admitted profile.
    #[error("Anthropic profile binding mismatch")]
    ProfileBindingMismatch,
    /// The call is not exactly the streaming text capability.
    #[error("Anthropic text-only capability required")]
    UnsupportedCapability,
    /// Profile and pricing extension was changed or contains extra fields.
    #[error("Anthropic profile extension mismatch")]
    ForbiddenExtension,
    /// History is empty or not alternating user/assistant text.
    #[error("Anthropic text context is invalid")]
    InvalidContext,
    /// A profile request bound was exceeded.
    #[error("Anthropic request bound exceeded")]
    BoundExceeded,
    /// Credential-free JSON serialization failed.
    #[error("Anthropic request serialization failed")]
    Serialization,
}

/// Gemini request rendering failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GeminiRenderError {
    /// Provider, model or revision differs from the admitted profile.
    #[error("Gemini profile binding mismatch")]
    ProfileBindingMismatch,
    /// The call is not exactly the streaming text capability.
    #[error("Gemini text-only capability required")]
    UnsupportedCapability,
    /// Profile and pricing extension was changed or contains extra fields.
    #[error("Gemini profile extension mismatch")]
    ForbiddenExtension,
    /// History is empty or not alternating user/assistant text.
    #[error("Gemini text context is invalid")]
    InvalidContext,
    /// A profile request bound was exceeded.
    #[error("Gemini request bound exceeded")]
    BoundExceeded,
    /// Credential-free JSON serialization failed.
    #[error("Gemini request serialization failed")]
    Serialization,
}

/// Credential-free Anthropic Messages renderer.
#[derive(Debug, Clone)]
pub struct AnthropicMessagesRenderer {
    profile: AnthropicMessagesProfile,
}

impl AnthropicMessagesRenderer {
    /// Binds a renderer to one admitted profile.
    pub const fn new(profile: AnthropicMessagesProfile) -> Self {
        Self { profile }
    }
    /// Returns the exact profile extension required on calls.
    pub fn binding_extension(&self) -> Value {
        self.profile.binding_extension()
    }
    /// Renders a bounded streaming `/v1/messages` request.
    pub fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, AnthropicRenderError> {
        common::validate_call(
            call,
            &self.profile,
            AnthropicRenderError::ProfileBindingMismatch,
            AnthropicRenderError::UnsupportedCapability,
            AnthropicRenderError::ForbiddenExtension,
            AnthropicRenderError::BoundExceeded,
        )?;
        let messages = anthropic::render_messages(
            call,
            &self.profile,
            AnthropicRenderError::InvalidContext,
            AnthropicRenderError::BoundExceeded,
        )?;
        let request = anthropic::Request {
            model: self.profile.model_id(),
            max_tokens: call.max_output_tokens(),
            messages,
            stream: true,
        };
        common::prepare_json(call, &request, self.profile.limits().max_request_bytes()).map_err(
            |error| match error {
                common::PrepareFailure::Bound => AnthropicRenderError::BoundExceeded,
                common::PrepareFailure::Serialization => AnthropicRenderError::Serialization,
            },
        )
    }
}

/// Credential-free Gemini renderer.
#[derive(Debug, Clone)]
pub struct GeminiRenderer {
    profile: GeminiProfile,
}

impl GeminiRenderer {
    /// Binds a renderer to one admitted profile.
    pub const fn new(profile: GeminiProfile) -> Self {
        Self { profile }
    }
    /// Returns the exact profile extension required on calls.
    pub fn binding_extension(&self) -> Value {
        self.profile.binding_extension()
    }
    /// Renders a bounded streaming `streamGenerateContent` request body.
    pub fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, GeminiRenderError> {
        common::validate_call(
            call,
            &self.profile,
            GeminiRenderError::ProfileBindingMismatch,
            GeminiRenderError::UnsupportedCapability,
            GeminiRenderError::ForbiddenExtension,
            GeminiRenderError::BoundExceeded,
        )?;
        let contents = gemini::render_contents(
            call,
            &self.profile,
            GeminiRenderError::InvalidContext,
            GeminiRenderError::BoundExceeded,
        )?;
        let request = gemini::Request {
            contents,
            generation_config: gemini::GenerationConfig {
                max_output_tokens: call.max_output_tokens(),
            },
        };
        common::prepare_json(call, &request, self.profile.limits().max_request_bytes()).map_err(
            |error| match error {
                common::PrepareFailure::Bound => GeminiRenderError::BoundExceeded,
                common::PrepareFailure::Serialization => GeminiRenderError::Serialization,
            },
        )
    }
}
