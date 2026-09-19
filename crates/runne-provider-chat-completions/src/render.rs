use crate::{ChatCompletionsProfile, ChatCompletionsThinkingMode};
use runne_provider::{
    PrepareError, PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderCapability,
    ProviderInputRole,
};
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

/// Bounded text renderer failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ChatCompletionsRenderError {
    /// Call identity differs from the exact profile.
    #[error("Chat Completions profile binding mismatch")]
    ProfileBindingMismatch,
    /// Tool, vision or another unsupported capability was requested.
    #[error("Chat Completions capability unsupported")]
    UnsupportedCapability,
    /// Extension contains fields outside the exact binding.
    #[error("Chat Completions extension forbidden")]
    ForbiddenExtension,
    /// Context is empty or not canonical.
    #[error("Chat Completions context invalid")]
    InvalidContext,
    /// A profile bound was exceeded.
    #[error("Chat Completions request exceeds bound")]
    BoundExceeded,
    /// Serialization failed.
    #[error("Chat Completions request rendering failed")]
    Serialization,
}
/// Renderer shared by all fixed Chat Completions profiles.
#[derive(Debug, Clone)]
pub struct ChatCompletionsRenderer {
    profile: ChatCompletionsProfile,
}
impl ChatCompletionsRenderer {
    /// Binds the renderer to one validated profile.
    ///
    /// # Errors
    /// Returns the profile validation error when the supplied profile is invalid.
    pub fn new(
        profile: ChatCompletionsProfile,
    ) -> Result<Self, crate::ChatCompletionsProfileError> {
        profile.validate()?;
        Ok(Self { profile })
    }

    /// Builds credential-free bounded JSON request bytes.
    ///
    /// # Errors
    /// Returns an error when the call is not bound to this profile or exceeds its bounds.
    pub fn prepare(
        &self,
        call: &ProviderCall,
    ) -> Result<PreparedRequest, ChatCompletionsRenderError> {
        if call.model_ref().provider_id().as_str() != self.profile.provider_id()
            || call.model_ref().model_id() != self.profile.model_id()
            || call.model_ref().revision() != self.profile.model_revision()
        {
            return Err(ChatCompletionsRenderError::ProfileBindingMismatch);
        }
        if call.required_capabilities() != [ProviderCapability::Streaming] {
            return Err(ChatCompletionsRenderError::UnsupportedCapability);
        }
        let expected = self.profile.binding_extension();
        if call.extension() != &expected {
            return Err(ChatCompletionsRenderError::ForbiddenExtension);
        }
        if call.max_output_tokens() > self.profile.max_output_tokens() {
            return Err(ChatCompletionsRenderError::BoundExceeded);
        }
        let mut messages = Vec::new();
        let mut expected_role = ProviderInputRole::User;
        let mut total = 0usize;
        for input in call.text_inputs() {
            if input.role() != expected_role
                || input.role() == ProviderInputRole::Developer
                || input.text().len() > self.profile.max_input_entry_bytes()
            {
                return Err(ChatCompletionsRenderError::InvalidContext);
            }
            total = total
                .checked_add(input.text().len())
                .ok_or(ChatCompletionsRenderError::BoundExceeded)?;
            if total > self.profile.max_input_bytes()
                || messages.len() >= self.profile.max_input_entries()
            {
                return Err(ChatCompletionsRenderError::BoundExceeded);
            }
            messages.push(Message {
                role: match input.role() {
                    ProviderInputRole::User => "user",
                    ProviderInputRole::Assistant => "assistant",
                    ProviderInputRole::Developer => unreachable!(),
                },
                content: input.text(),
                reasoning_content: (input.role() == ProviderInputRole::Assistant
                    && self.profile.thinking_mode()
                        == ChatCompletionsThinkingMode::DeepSeekReasoningContentRequired)
                    .then_some(""),
            });
            expected_role = match expected_role {
                ProviderInputRole::User => ProviderInputRole::Assistant,
                ProviderInputRole::Assistant | ProviderInputRole::Developer => {
                    ProviderInputRole::User
                }
            };
        }
        if messages.is_empty() || expected_role != ProviderInputRole::Assistant {
            return Err(ChatCompletionsRenderError::InvalidContext);
        }
        let request = Request {
            model: self.profile.model_id(),
            messages,
            max_tokens: call.max_output_tokens(),
            stream: true,
            stream_options: self
                .profile
                .include_stream_usage()
                .then_some(StreamOptions {
                    include_usage: true,
                }),
            enable_thinking: (self.profile.thinking_mode()
                == ChatCompletionsThinkingMode::EnableThinkingFalse)
                .then_some(false),
            thinking: (self.profile.thinking_mode()
                == ChatCompletionsThinkingMode::ThinkingObjectDisabled)
                .then_some(Thinking { kind: "disabled" }),
        };
        let mut bytes =
            serde_json::to_vec(&request).map_err(|_| ChatCompletionsRenderError::Serialization)?;
        bytes.push(b'\n');
        if bytes.len() > self.profile.max_request_bytes() {
            return Err(ChatCompletionsRenderError::BoundExceeded);
        }
        PreparedRequest::from_rendered_call_for_digest_version(
            call,
            ProviderCallDigestVersion::V2,
            bytes,
        )
        .map_err(|error| match error {
            PrepareError::RenderedRequestBound => ChatCompletionsRenderError::BoundExceeded,
            _ => ChatCompletionsRenderError::Serialization,
        })
    }
    /// Returns the exact binding extension expected by this renderer.
    #[must_use]
    pub fn binding_extension(&self) -> Value {
        self.profile.binding_extension()
    }
}
impl ChatCompletionsProfile {
    fn binding_extension(&self) -> Value {
        json!({ "profile_id": self.profile_id(), "profile_digest": hex::encode(self.profile_digest()), "pricing_revision_digest": hex::encode(self.pricing_revision_digest()) })
    }
}
#[derive(Serialize)]
struct Request<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    max_tokens: u32,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_options: Option<StreamOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enable_thinking: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<Thinking<'a>>,
}
#[derive(Serialize)]
struct StreamOptions {
    include_usage: bool,
}
#[derive(Serialize)]
struct Thinking<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider::{
        ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
        ProviderTextInput,
    };

    fn profile(mode: ChatCompletionsThinkingMode) -> ChatCompletionsProfile {
        let profile = ChatCompletionsProfile::new_with_thinking(
            "test-provider",
            "test-profile/1",
            "test-model",
            "2026-09-14",
            "https://provider.example",
            "/compatible-mode/v1/chat/completions",
            [1; 32],
            [2; 32],
            4,
            100,
            400,
            100,
            1024,
            512,
            mode,
        );
        ChatCompletionsProfile::new_with_thinking(
            "test-provider",
            "test-profile/1",
            "test-model",
            "2026-09-14",
            "https://provider.example",
            "/compatible-mode/v1/chat/completions",
            profile.recomputed_profile_digest(),
            profile.recomputed_pricing_revision_digest(),
            4,
            100,
            400,
            100,
            1024,
            512,
            mode,
        )
    }

    fn call(renderer: &ChatCompletionsRenderer) -> ProviderCall {
        ProviderCall::new(
            ProviderCallId::from_bytes([7; 16]),
            ModelRef::new(
                ProviderId::new("test-provider").unwrap(),
                "test-model",
                "2026-09-14",
            )
            .unwrap(),
            [9; 32],
            8,
            renderer.binding_extension(),
        )
        .unwrap()
        .with_text_inputs(vec![
            ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
        ])
        .unwrap()
        .with_required_capabilities(vec![ProviderCapability::Streaming])
    }

    #[test]
    fn request_has_usage_stream_option_and_qwen_thinking_switch() {
        let renderer =
            ChatCompletionsRenderer::new(profile(ChatCompletionsThinkingMode::EnableThinkingFalse))
                .unwrap();
        let value: Value =
            serde_json::from_slice(renderer.prepare(&call(&renderer)).unwrap().rendered_bytes())
                .unwrap();
        assert_eq!(value["stream_options"]["include_usage"], true);
        assert_eq!(value["enable_thinking"], false);
        assert!(value.get("thinking").is_none());
    }

    #[test]
    fn request_has_zai_thinking_object_without_qwen_field() {
        let renderer = ChatCompletionsRenderer::new(profile(
            ChatCompletionsThinkingMode::ThinkingObjectDisabled,
        ))
        .unwrap();
        let value: Value =
            serde_json::from_slice(renderer.prepare(&call(&renderer)).unwrap().rendered_bytes())
                .unwrap();
        assert_eq!(value["stream_options"]["include_usage"], true);
        assert_eq!(value["thinking"]["type"], "disabled");
        assert!(value.get("enable_thinking").is_none());
    }

    #[test]
    fn deepseek_compatible_history_has_required_reasoning_content() {
        let renderer = ChatCompletionsRenderer::new(profile(
            ChatCompletionsThinkingMode::DeepSeekReasoningContentRequired,
        ))
        .unwrap();
        let mut request = call(&renderer);
        request = request
            .with_text_inputs(vec![
                ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
                ProviderTextInput::new(ProviderInputRole::Assistant, "answer").unwrap(),
                ProviderTextInput::new(ProviderInputRole::User, "follow-up").unwrap(),
            ])
            .unwrap();
        let value: Value =
            serde_json::from_slice(renderer.prepare(&request).unwrap().rendered_bytes()).unwrap();
        assert_eq!(value["messages"][1]["reasoning_content"], "");
        assert!(value["messages"][0].get("reasoning_content").is_none());
    }
}
#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_content: Option<&'a str>,
}
