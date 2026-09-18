use sha2::{Digest, Sha256};

use crate::profile::{
    ChatCompletionsAccounting, ChatCompletionsBillingMode, ChatCompletionsProfile,
    ChatCompletionsThinkingMode,
};

const PROFILE_DOMAIN: &[u8] = b"GOCODE_CHAT_COMPLETIONS_PROFILE_V1\0";
const PRICING_DOMAIN: &[u8] = b"GOCODE_CHAT_COMPLETIONS_PRICING_V1\0";
const ROUNDING_REVISION: &str = "ceil-v1";

impl ChatCompletionsProfile {
    /// Recomputes the profile digest from every immutable wire and accounting field.
    #[must_use]
    pub fn recomputed_profile_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_DOMAIN);
        for value in [
            self.provider_id(),
            self.profile_id(),
            self.model_id(),
            self.model_revision(),
            self.origin(),
            self.path(),
        ] {
            update_text(&mut hasher, value);
        }
        for value in [
            self.max_input_entries() as u64,
            self.max_input_entry_bytes() as u64,
            self.max_input_bytes() as u64,
            u64::from(self.max_output_tokens()),
            self.max_request_bytes() as u64,
            self.max_frame_bytes() as u64,
        ] {
            hasher.update(value.to_be_bytes());
        }
        if let Some(limits) = self.model_limits() {
            hasher.update([1]);
            for value in [
                limits.context_tokens(),
                limits.max_input_tokens(),
                limits.max_model_output_tokens(),
                limits.protocol_overhead_tokens(),
            ] {
                hasher.update(value.to_be_bytes());
            }
        }
        if let Some(mode) = self.billing_mode() {
            hasher.update([10 + billing_mode_tag(mode)]);
        }
        update_accounting(&mut hasher, self.accounting());
        hasher.update([thinking_tag(self.thinking_mode())]);
        if !self.include_stream_usage() {
            hasher.update([0xff]);
        }
        hasher.finalize().into()
    }

    /// Recomputes the pricing digest from the selected model and exact rates.
    #[must_use]
    pub fn recomputed_pricing_revision_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PRICING_DOMAIN);
        for value in [
            self.provider_id(),
            self.profile_id(),
            self.model_id(),
            self.model_revision(),
            ROUNDING_REVISION,
            self.currency(),
        ] {
            update_text(&mut hasher, value);
        }
        update_accounting(&mut hasher, self.accounting());
        hasher.finalize().into()
    }
}

fn update_text(hasher: &mut Sha256, value: &str) {
    if let Ok(length) = u32::try_from(value.len()) {
        hasher.update(length.to_be_bytes());
    } else {
        hasher.update(u32::MAX.to_be_bytes());
        hasher.update([0xff]);
    }
    hasher.update(value.as_bytes());
}

fn update_accounting(hasher: &mut Sha256, accounting: ChatCompletionsAccounting) {
    match accounting {
        ChatCompletionsAccounting::SubscriptionQuotaExternallyMetered => {
            hasher.update([0]);
            hasher.update([0_u8; 24]);
        }
        ChatCompletionsAccounting::Payg {
            input_micros_per_million,
            output_micros_per_million,
            cached_input_micros_per_million,
        } => {
            hasher.update([1]);
            for value in [
                input_micros_per_million,
                output_micros_per_million,
                cached_input_micros_per_million,
            ] {
                hasher.update(value.to_be_bytes());
            }
        }
        ChatCompletionsAccounting::ExternallyBilledUnpriced => {
            hasher.update([2]);
            hasher.update([0_u8; 24]);
        }
    }
}

const fn thinking_tag(thinking: ChatCompletionsThinkingMode) -> u8 {
    match thinking {
        ChatCompletionsThinkingMode::None => 0,
        ChatCompletionsThinkingMode::EnableThinkingFalse => 1,
        ChatCompletionsThinkingMode::ThinkingObjectDisabled => 2,
        ChatCompletionsThinkingMode::DeepSeekReasoningContentRequired => 3,
    }
}

const fn billing_mode_tag(mode: ChatCompletionsBillingMode) -> u8 {
    match mode {
        ChatCompletionsBillingMode::ExternalPayg => 0,
        ChatCompletionsBillingMode::UnifiedBilling => 1,
        ChatCompletionsBillingMode::StoredByok => 2,
    }
}
