use super::ChatCompletionsProfile;

/// Profile validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChatCompletionsProfileError {
    /// Profile has an unsafe endpoint or empty bound.
    #[error("invalid Chat Completions profile")]
    Invalid,
}

impl ChatCompletionsProfile {
    /// Validates endpoint and bounded request invariants.
    ///
    /// # Errors
    /// Returns `Invalid` when endpoint, digest, or model-limit invariants fail.
    pub fn validate(&self) -> Result<(), ChatCompletionsProfileError> {
        if !self.origin.starts_with("https://")
            || self.origin.ends_with('/')
            || self.origin[8..].contains("//")
            || !self.path.starts_with('/')
            || self.path.starts_with("//")
            || self.path.contains(['?', '#'])
            || self.path.ends_with("/v1/responses")
            || self.profile_id.is_empty()
            || self.model_id.is_empty()
            || self.model_revision.is_empty()
            || self.max_request_bytes == 0
            || self.max_frame_bytes == 0
            || self.max_frame_bytes > self.max_request_bytes
            || self.max_output_tokens == 0
        {
            return Err(ChatCompletionsProfileError::Invalid);
        }
        if self.profile_digest() != self.recomputed_profile_digest()
            || self.pricing_revision_digest() != self.recomputed_pricing_revision_digest()
        {
            return Err(ChatCompletionsProfileError::Invalid);
        }
        if let Some(limits) = self.model_limits() {
            if !limits.is_valid(self.max_output_tokens()) {
                return Err(ChatCompletionsProfileError::Invalid);
            }
            let Some(max_input_bytes) = usize::try_from(limits.max_input_tokens()).ok() else {
                return Err(ChatCompletionsProfileError::Invalid);
            };
            if self.max_input_bytes() > max_input_bytes {
                return Err(ChatCompletionsProfileError::Invalid);
            }
        }
        Ok(())
    }
}
