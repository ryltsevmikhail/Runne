use super::{
    ChatCompletionsAccounting, ChatCompletionsBillingMode, ChatCompletionsModelLimits,
    ChatCompletionsProfile, ChatCompletionsThinkingMode, Cow,
};

#[allow(clippy::must_use_candidate)]
impl ChatCompletionsProfile {
    /// Creates an owned configured profile with attested model limits.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new_owned_with_accounting(
        provider_id: String,
        profile_id: String,
        model_id: String,
        model_revision: String,
        origin: String,
        path: String,
        profile_digest: [u8; 32],
        pricing_digest: [u8; 32],
        max_input_entries: usize,
        max_input_entry_bytes: usize,
        max_input_bytes: usize,
        max_output_tokens: u32,
        max_request_bytes: usize,
        max_frame_bytes: usize,
        model_limits: ChatCompletionsModelLimits,
        billing_mode: ChatCompletionsBillingMode,
        accounting: ChatCompletionsAccounting,
        thinking_mode: ChatCompletionsThinkingMode,
    ) -> Self {
        Self {
            provider_id: Cow::Owned(provider_id),
            profile_id: Cow::Owned(profile_id),
            model_id: Cow::Owned(model_id),
            model_revision: Cow::Owned(model_revision),
            origin: Cow::Owned(origin),
            path: Cow::Owned(path),
            profile_digest,
            pricing_digest,
            max_input_entries,
            max_input_entry_bytes,
            max_input_bytes,
            max_output_tokens,
            max_request_bytes,
            max_frame_bytes,
            accounting,
            thinking_mode,
            include_stream_usage: true,
            model_limits: Some(model_limits),
            billing_mode: Some(billing_mode),
        }
    }

    /// Replaces supplied digests with the canonical digests of this profile.
    #[must_use]
    pub fn with_recomputed_digests(mut self) -> Self {
        self.profile_digest = self.recomputed_profile_digest();
        self.pricing_digest = self.recomputed_pricing_revision_digest();
        self
    }

    /// Returns the provider identity.
    pub fn provider_id(&self) -> &str {
        self.provider_id.as_ref()
    }
    /// Returns the exact profile ID.
    pub fn profile_id(&self) -> &str {
        self.profile_id.as_ref()
    }
    /// Returns the model ID sent to the provider.
    pub fn model_id(&self) -> &str {
        self.model_id.as_ref()
    }
    /// Returns the immutable model revision.
    pub fn model_revision(&self) -> &str {
        self.model_revision.as_ref()
    }
    /// Returns the fixed HTTPS origin.
    pub fn origin(&self) -> &str {
        self.origin.as_ref()
    }
    /// Returns the fixed request path.
    pub fn path(&self) -> &str {
        self.path.as_ref()
    }
    /// Returns the exact profile digest.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }
    /// Returns the accounting contract digest.
    pub const fn pricing_revision_digest(&self) -> [u8; 32] {
        self.pricing_digest
    }
    /// Returns the accounting contract kind.
    pub const fn accounting(&self) -> ChatCompletionsAccounting {
        self.accounting
    }
    /// Returns the ISO 4217 no-currency marker.
    pub const fn currency(&self) -> &'static str {
        match self.accounting {
            ChatCompletionsAccounting::Payg { .. } => "USD",
            ChatCompletionsAccounting::SubscriptionQuotaExternallyMetered
            | ChatCompletionsAccounting::ExternallyBilledUnpriced => "XXX",
        }
    }
    /// Returns the maximum committed entries.
    pub const fn max_input_entries(&self) -> usize {
        self.max_input_entries
    }
    /// Returns the maximum committed entry bytes.
    pub const fn max_input_entry_bytes(&self) -> usize {
        self.max_input_entry_bytes
    }
    /// Returns the maximum aggregate input bytes.
    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }
    /// Returns the output token ceiling.
    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }
    /// Returns the serialized request ceiling.
    pub const fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }
    /// Returns the normalized frame ceiling.
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
    /// Returns the attested model-context limits, when present.
    pub const fn model_limits(&self) -> Option<ChatCompletionsModelLimits> {
        self.model_limits
    }
    /// Returns the configured billing route, when this is a configured profile.
    pub const fn billing_mode(&self) -> Option<ChatCompletionsBillingMode> {
        self.billing_mode
    }
    /// Returns the exact request encoding for disabled reasoning.
    pub const fn thinking_mode(&self) -> ChatCompletionsThinkingMode {
        self.thinking_mode
    }
    /// Returns whether the provider accepts the `OpenAI` stream usage extension.
    pub const fn include_stream_usage(&self) -> bool {
        self.include_stream_usage
    }
    /// Returns a profile with the stream usage extension explicitly disabled.
    #[must_use]
    pub const fn with_stream_usage(mut self, include: bool) -> Self {
        self.include_stream_usage = include;
        self
    }
}
