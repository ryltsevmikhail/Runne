//! Exact provider-mode activation selected before daemon readiness.

use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};

/// Validated non-secret provider activation retained by the daemon composition root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderActivation {
    /// Credential-free deterministic compatibility mode.
    Deterministic(ProviderActivationBindingV1),
    /// Exact OpenAI Responses text mode. Execution wiring is admitted separately.
    OpenAiResponsesText(ProviderActivationBindingV1),
    /// Exact DeepSeek Responses text mode. Execution wiring is admitted separately.
    DeepSeekResponsesText(ProviderActivationBindingV1),
}

impl ProviderActivation {
    /// Returns the V1 deterministic compatibility activation.
    #[must_use]
    pub fn deterministic_v1() -> Self {
        Self::Deterministic(ProviderActivationBindingV1::deterministic_v1())
    }

    /// Classifies an already exact, decoded protocol V2 binding.
    #[must_use]
    pub fn from_binding(binding: ProviderActivationBindingV1) -> Self {
        match binding.mode() {
            ProviderActivationModeV1::DeterministicV1 => Self::Deterministic(binding),
            ProviderActivationModeV1::OpenAiResponsesTextV1 => Self::OpenAiResponsesText(binding),
            ProviderActivationModeV1::DeepSeekResponsesTextV1 => {
                Self::DeepSeekResponsesText(binding)
            }
        }
    }

    /// Returns the exact non-secret mode/profile binding.
    #[must_use]
    pub const fn binding(&self) -> &ProviderActivationBindingV1 {
        match self {
            Self::Deterministic(binding)
            | Self::OpenAiResponsesText(binding)
            | Self::DeepSeekResponsesText(binding) => binding,
        }
    }

    /// Reports whether the exact OpenAI execution path is required.
    #[must_use]
    pub const fn requires_openai_execution(&self) -> bool {
        matches!(self, Self::OpenAiResponsesText(_))
    }

    /// Reports whether the exact DeepSeek execution path is required.
    #[must_use]
    pub const fn requires_deepseek_execution(&self) -> bool {
        matches!(self, Self::DeepSeekResponsesText(_))
    }
}
