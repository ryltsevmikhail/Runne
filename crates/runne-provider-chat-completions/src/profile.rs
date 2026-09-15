use std::borrow::Cow;

use crate::profile_limits::ChatCompletionsModelLimits;

/// Pricing semantics for subscription-backed provider plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatCompletionsAccounting {
    /// Usage is normalized, while credits and monetary settlement remain vendor-owned.
    SubscriptionQuotaExternallyMetered,
    /// PAYG rates pinned in micro-USD per million tokens.
    Payg {
        /// Input token rate.
        input_micros_per_million: u64,
        /// Output token rate.
        output_micros_per_million: u64,
        /// Cached input token rate.
        cached_input_micros_per_million: u64,
    },
    /// Provider billing is external and no trusted price is available.
    ExternallyBilledUnpriced,
}
/// Billing route bound into an operator-configured profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatCompletionsBillingMode {
    /// External provider PAYG billing.
    ExternalPayg,
    /// Cloudflare AI Gateway unified billing.
    UnifiedBilling,
    /// Cloudflare AI Gateway stored BYOK billing.
    StoredByok,
}
/// Provider-specific thinking field emitted by the text-only request renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatCompletionsThinkingMode {
    /// Provider default; no provider-specific thinking field is emitted.
    None,
    /// Qwen-compatible boolean switch.
    EnableThinkingFalse,
    /// Z.ai-compatible object form.
    ThinkingObjectDisabled,
    /// DeepSeek-compatible providers require this field on assistant history.
    DeepSeekReasoningContentRequired,
}
/// Immutable allowlisted Chat Completions profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatCompletionsProfile {
    provider_id: Cow<'static, str>,
    profile_id: Cow<'static, str>,
    model_id: Cow<'static, str>,
    model_revision: Cow<'static, str>,
    origin: Cow<'static, str>,
    path: Cow<'static, str>,
    profile_digest: [u8; 32],
    pricing_digest: [u8; 32],
    max_input_entries: usize,
    max_input_entry_bytes: usize,
    max_input_bytes: usize,
    max_output_tokens: u32,
    max_request_bytes: usize,
    max_frame_bytes: usize,
    model_limits: Option<ChatCompletionsModelLimits>,
    billing_mode: Option<ChatCompletionsBillingMode>,
    accounting: ChatCompletionsAccounting,
    thinking_mode: ChatCompletionsThinkingMode,
    include_stream_usage: bool,
}
impl ChatCompletionsProfile {
    /// Creates a validated exact profile. Endpoint values are compile-time provider data.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        provider_id: &'static str,
        profile_id: &'static str,
        model_id: &'static str,
        model_revision: &'static str,
        origin: &'static str,
        path: &'static str,
        profile_digest: [u8; 32],
        pricing_digest: [u8; 32],
        max_input_entries: usize,
        max_input_entry_bytes: usize,
        max_input_bytes: usize,
        max_output_tokens: u32,
        max_request_bytes: usize,
        max_frame_bytes: usize,
    ) -> Self {
        Self::new_with_thinking(
            provider_id,
            profile_id,
            model_id,
            model_revision,
            origin,
            path,
            profile_digest,
            pricing_digest,
            max_input_entries,
            max_input_entry_bytes,
            max_input_bytes,
            max_output_tokens,
            max_request_bytes,
            max_frame_bytes,
            ChatCompletionsThinkingMode::EnableThinkingFalse,
        )
    }
    /// Creates a profile with an exact provider-specific thinking encoding.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new_with_thinking(
        provider_id: &'static str,
        profile_id: &'static str,
        model_id: &'static str,
        model_revision: &'static str,
        origin: &'static str,
        path: &'static str,
        profile_digest: [u8; 32],
        pricing_digest: [u8; 32],
        max_input_entries: usize,
        max_input_entry_bytes: usize,
        max_input_bytes: usize,
        max_output_tokens: u32,
        max_request_bytes: usize,
        max_frame_bytes: usize,
        thinking_mode: ChatCompletionsThinkingMode,
    ) -> Self {
        Self {
            provider_id: Cow::Borrowed(provider_id),
            profile_id: Cow::Borrowed(profile_id),
            model_id: Cow::Borrowed(model_id),
            model_revision: Cow::Borrowed(model_revision),
            origin: Cow::Borrowed(origin),
            path: Cow::Borrowed(path),
            profile_digest,
            pricing_digest,
            max_input_entries,
            max_input_entry_bytes,
            max_input_bytes,
            max_output_tokens,
            max_request_bytes,
            max_frame_bytes,
            accounting: ChatCompletionsAccounting::SubscriptionQuotaExternallyMetered,
            thinking_mode,
            include_stream_usage: true,
            model_limits: None,
            billing_mode: None,
        }
    }

    /// Creates a profile with explicit billing semantics.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new_with_accounting(
        provider_id: &'static str,
        profile_id: &'static str,
        model_id: &'static str,
        model_revision: &'static str,
        origin: &'static str,
        path: &'static str,
        profile_digest: [u8; 32],
        pricing_digest: [u8; 32],
        max_input_entries: usize,
        max_input_entry_bytes: usize,
        max_input_bytes: usize,
        max_output_tokens: u32,
        max_request_bytes: usize,
        max_frame_bytes: usize,
        accounting: ChatCompletionsAccounting,
        thinking_mode: ChatCompletionsThinkingMode,
    ) -> Self {
        let mut profile = Self::new_with_thinking(
            provider_id,
            profile_id,
            model_id,
            model_revision,
            origin,
            path,
            profile_digest,
            pricing_digest,
            max_input_entries,
            max_input_entry_bytes,
            max_input_bytes,
            max_output_tokens,
            max_request_bytes,
            max_frame_bytes,
            thinking_mode,
        );
        profile.accounting = accounting;
        profile
    }
}

#[path = "profile_owned.rs"]
mod owned;

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;

#[path = "profile_pricing.rs"]
mod pricing;
#[path = "profile_validation.rs"]
mod validation;

pub use validation::ChatCompletionsProfileError;
