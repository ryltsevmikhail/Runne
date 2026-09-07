//! Terminal usage accounting for one generation: prompt and output
//! token counts as reported by the context, never estimated.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub output_tokens: u64,
}

impl TokenUsage {
    pub fn new(prompt_tokens: u64, output_tokens: u64) -> Self {
        Self {
            prompt_tokens,
            output_tokens,
        }
    }
}
