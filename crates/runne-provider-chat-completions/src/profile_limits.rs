//! Attested model limits used by operator-configured profiles.

/// Model-context limits owned by the configured provider adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChatCompletionsModelLimits {
    context: u32,
    max_input: u32,
    max_model_output: u32,
    protocol_overhead: u32,
}

impl ChatCompletionsModelLimits {
    /// Creates limits that must be validated before profile construction.
    #[must_use]
    pub const fn new(
        context_tokens: u32,
        max_input_tokens: u32,
        max_model_output_tokens: u32,
        protocol_overhead_tokens: u32,
    ) -> Self {
        Self {
            context: context_tokens,
            max_input: max_input_tokens,
            max_model_output: max_model_output_tokens,
            protocol_overhead: protocol_overhead_tokens,
        }
    }

    /// Attested model context window in tokens.
    #[must_use]
    pub const fn context_tokens(self) -> u32 {
        self.context
    }
    /// Upper input-token bound used by this profile.
    #[must_use]
    pub const fn max_input_tokens(self) -> u32 {
        self.max_input
    }
    /// Provider model's maximum output-token capability.
    #[must_use]
    pub const fn max_model_output_tokens(self) -> u32 {
        self.max_model_output
    }
    /// Reserved bounded protocol overhead in tokens.
    #[must_use]
    pub const fn protocol_overhead_tokens(self) -> u32 {
        self.protocol_overhead
    }

    pub(crate) fn is_valid(self, selected_output_tokens: u32) -> bool {
        self.context > 0
            && self.max_input > 0
            && self.max_model_output > 0
            && self.protocol_overhead > 0
            && selected_output_tokens > 0
            && selected_output_tokens <= self.max_model_output
            && self
                .max_input
                .checked_add(selected_output_tokens)
                .and_then(|value| value.checked_add(self.protocol_overhead))
                .is_some_and(|value| value <= self.context)
    }
}
