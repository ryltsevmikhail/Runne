//! Bounds and billing inputs for configured Chat Completions endpoints.

use crate::{ChatCompletionsAccounting, ChatCompletionsBillingMode, ChatCompletionsModelLimits};

/// Owner-supplied, model-specific bounds for a configured endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfiguredChatModelLimits {
    model: ChatCompletionsModelLimits,
    max_output_tokens: u32,
    max_input_entries: usize,
    max_input_entry_bytes: usize,
    max_input_bytes: usize,
    max_request_bytes: usize,
    max_response_frame_bytes: usize,
}

impl ConfiguredChatModelLimits {
    /// Creates the complete model, request, input and response-frame contract.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        context_tokens: u32,
        max_input_tokens: u32,
        max_model_output_tokens: u32,
        max_output_tokens: u32,
        protocol_overhead_tokens: u32,
        max_input_entries: usize,
        max_input_entry_bytes: usize,
        max_input_bytes: usize,
        max_request_bytes: usize,
        max_response_frame_bytes: usize,
    ) -> Self {
        Self {
            model: ChatCompletionsModelLimits::new(
                context_tokens,
                max_input_tokens,
                max_model_output_tokens,
                protocol_overhead_tokens,
            ),
            max_output_tokens,
            max_input_entries,
            max_input_entry_bytes,
            max_input_bytes,
            max_request_bytes,
            max_response_frame_bytes,
        }
    }

    pub(crate) fn validate(self) -> bool {
        self.model.is_valid(self.max_output_tokens)
            && self.max_input_entries > 0
            && self.max_input_entry_bytes > 0
            && self.max_input_bytes > 0
            && self.max_input_entry_bytes <= self.max_input_bytes
            && self.max_request_bytes > 0
            && self.max_response_frame_bytes > 0
            && self.max_response_frame_bytes <= self.max_request_bytes
            && usize::try_from(self.model.max_input_tokens())
                .is_ok_and(|value| self.max_input_bytes <= value)
    }

    pub(crate) const fn model(self) -> ChatCompletionsModelLimits {
        self.model
    }
    pub(crate) const fn max_output_tokens(self) -> u32 {
        self.max_output_tokens
    }
    pub(crate) const fn max_input_entries(self) -> usize {
        self.max_input_entries
    }
    pub(crate) const fn max_input_entry_bytes(self) -> usize {
        self.max_input_entry_bytes
    }
    pub(crate) const fn max_input_bytes(self) -> usize {
        self.max_input_bytes
    }
    pub(crate) const fn max_request_bytes(self) -> usize {
        self.max_request_bytes
    }
    pub(crate) const fn max_response_frame_bytes(self) -> usize {
        self.max_response_frame_bytes
    }
}

pub const fn validate_payg(
    accounting: ChatCompletionsAccounting,
) -> Result<(), super::ConfiguredChatProfileError> {
    match accounting {
        ChatCompletionsAccounting::Payg {
            input_micros_per_million,
            output_micros_per_million,
            cached_input_micros_per_million,
        } if input_micros_per_million > 0
            && output_micros_per_million > 0
            && cached_input_micros_per_million <= input_micros_per_million =>
        {
            Ok(())
        }
        ChatCompletionsAccounting::ExternallyBilledUnpriced => {
            Err(super::ConfiguredChatProfileError::Unpriced)
        }
        _ => Err(super::ConfiguredChatProfileError::UnsupportedBilling),
    }
}

pub const fn validate_gateway_billing(
    mode: ChatCompletionsBillingMode,
) -> Result<(), super::ConfiguredChatProfileError> {
    match mode {
        ChatCompletionsBillingMode::UnifiedBilling | ChatCompletionsBillingMode::StoredByok => {
            Ok(())
        }
        ChatCompletionsBillingMode::ExternalPayg => {
            Err(super::ConfiguredChatProfileError::InvalidBillingMode)
        }
    }
}
