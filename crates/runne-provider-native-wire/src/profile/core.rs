use serde_json::{Value, json};
use thiserror::Error;

/// Exact bounded request and response limits admitted for one native profile.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireLimits {
    max_input_entries: usize,
    max_input_entry_bytes: usize,
    max_input_bytes: usize,
    max_input_tokens: u64,
    max_output_tokens: u32,
    max_request_bytes: usize,
    max_frame_bytes: usize,
}

impl WireLimits {
    /// Creates a bounded limit set. Zero values are rejected by the profile constructors.
    pub const fn new(
        entries: usize,
        entry_bytes: usize,
        input_bytes: usize,
        output_tokens: u32,
        request_bytes: usize,
        frame_bytes: usize,
    ) -> Result<Self, NativeWireProfileError> {
        Self::new_with_input_tokens(
            entries,
            entry_bytes,
            input_bytes,
            input_bytes as u64,
            output_tokens,
            request_bytes,
            frame_bytes,
        )
    }
    /// Creates limits with a separate model-token input cap.
    pub const fn new_with_input_tokens(
        entries: usize,
        entry_bytes: usize,
        input_bytes: usize,
        input_tokens: u64,
        output_tokens: u32,
        request_bytes: usize,
        frame_bytes: usize,
    ) -> Result<Self, NativeWireProfileError> {
        if entries == 0
            || entry_bytes == 0
            || input_bytes == 0
            || input_tokens == 0
            || output_tokens == 0
            || request_bytes == 0
            || frame_bytes == 0
        {
            return Err(NativeWireProfileError::InvalidLimits);
        }
        Ok(Self {
            max_input_entries: entries,
            max_input_entry_bytes: entry_bytes,
            max_input_bytes: input_bytes,
            max_input_tokens: input_tokens,
            max_output_tokens: output_tokens,
            max_request_bytes: request_bytes,
            max_frame_bytes: frame_bytes,
        })
    }
    /// Maximum normalized input entries.
    pub const fn max_input_entries(self) -> usize {
        self.max_input_entries
    }
    /// Maximum bytes in one normalized input entry.
    pub const fn max_input_entry_bytes(self) -> usize {
        self.max_input_entry_bytes
    }
    /// Maximum aggregate normalized input bytes.
    pub const fn max_input_bytes(self) -> usize {
        self.max_input_bytes
    }
    /// Maximum input token budget bound to the model context window.
    pub const fn max_input_tokens(self) -> u64 {
        self.max_input_tokens
    }
    /// Maximum requested output tokens.
    pub const fn max_output_tokens(self) -> u32 {
        self.max_output_tokens
    }
    /// Maximum serialized request bytes.
    pub const fn max_request_bytes(self) -> usize {
        self.max_request_bytes
    }
    /// Maximum one SSE frame bytes.
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }
    /// Returns whether this input/output budget fits the model context.
    pub const fn fits_context(self, model_context_tokens: u64) -> bool {
        match self
            .max_input_tokens
            .checked_add(self.max_output_tokens as u64)
        {
            Some(total) => total <= model_context_tokens,
            None => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCore {
    provider_id: String,
    profile_id: String,
    model_id: String,
    revision: String,
    model_version_alias: Option<String>,
    profile_digest: [u8; 32],
    pricing_digest: [u8; 32],
    limits: WireLimits,
    accounting: NativeAccounting,
}

/// Immutable accounting contract for a native text profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAccounting {
    /// Usage is normalized, while billing remains provider-owned.
    SubscriptionQuotaExternallyMetered,
    /// PAYG rates in micro-USD per million tokens.
    Payg {
        /// Uncached input rate.
        input_micros_per_million: u64,
        /// Output rate.
        output_micros_per_million: u64,
        /// Cached-input rate.
        cached_input_micros_per_million: u64,
        /// Cache-write rate. The current renderer never emits cache writes.
        cache_write_micros_per_million: u64,
    },
    /// Explicit token-plan accounting with externally metered quota.
    TokenPlanQuotaExternallyMetered,
    /// No trusted rate was admitted for this profile.
    ExternallyBilledUnpriced,
}

impl ProfileCore {
    pub(crate) fn new(
        provider: &str,
        profile: &str,
        model: &str,
        revision: &str,
        profile_digest: [u8; 32],
        pricing_digest: [u8; 32],
        limits: WireLimits,
    ) -> Result<Self, NativeWireProfileError> {
        Self::new_with_accounting(
            provider,
            profile,
            model,
            revision,
            profile_digest,
            pricing_digest,
            limits,
            NativeAccounting::ExternallyBilledUnpriced,
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "compatibility constructor keeps the immutable native profile tuple explicit"
    )]
    pub(crate) fn new_with_accounting(
        provider: &str,
        profile: &str,
        model: &str,
        revision: &str,
        profile_digest: [u8; 32],
        pricing_digest: [u8; 32],
        limits: WireLimits,
        accounting: NativeAccounting,
    ) -> Result<Self, NativeWireProfileError> {
        if [provider, profile, model, revision]
            .iter()
            .any(|value| value.is_empty())
        {
            return Err(NativeWireProfileError::EmptyIdentity);
        }
        Ok(Self {
            provider_id: provider.to_owned(),
            profile_id: profile.to_owned(),
            model_id: model.to_owned(),
            revision: revision.to_owned(),
            model_version_alias: None,
            profile_digest,
            pricing_digest,
            limits,
            accounting,
        })
    }
    pub(crate) fn provider_id(&self) -> &str {
        &self.provider_id
    }
    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }
    pub(crate) fn model_id(&self) -> &str {
        &self.model_id
    }
    pub(crate) fn revision(&self) -> &str {
        &self.revision
    }
    pub(crate) fn model_version_alias(&self) -> Option<&str> {
        self.model_version_alias.as_deref()
    }
    pub(crate) fn with_model_version_alias(
        mut self,
        alias: &str,
    ) -> Result<Self, NativeWireProfileError> {
        if alias.is_empty() {
            return Err(NativeWireProfileError::EmptyIdentity);
        }
        self.model_version_alias = Some(alias.to_owned());
        Ok(self)
    }
    pub(crate) const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }
    pub(crate) const fn pricing_digest(&self) -> [u8; 32] {
        self.pricing_digest
    }
    pub(crate) const fn limits(&self) -> WireLimits {
        self.limits
    }
    pub(crate) const fn accounting(&self) -> NativeAccounting {
        self.accounting
    }
    pub(crate) fn extension(&self) -> Value {
        json!({ "profile_id": self.profile_id(), "profile_digest": hex::encode(self.profile_digest()), "pricing_revision_digest": hex::encode(self.pricing_digest()), "accounting": self.accounting.extension() })
    }
}

impl NativeAccounting {
    pub(crate) fn extension(self) -> Value {
        match self {
            Self::SubscriptionQuotaExternallyMetered => json!({"kind":"subscription_quota"}),
            Self::Payg {
                input_micros_per_million,
                output_micros_per_million,
                cached_input_micros_per_million,
                cache_write_micros_per_million,
            } => json!({
                "kind": "payg",
                "input_micros_per_million": input_micros_per_million,
                "output_micros_per_million": output_micros_per_million,
                "cached_input_micros_per_million": cached_input_micros_per_million,
                "cache_write_micros_per_million": cache_write_micros_per_million,
            }),
            Self::TokenPlanQuotaExternallyMetered => json!({"kind":"token_plan_quota"}),
            Self::ExternallyBilledUnpriced => json!({"kind":"unpriced"}),
        }
    }
}

/// Profile construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NativeWireProfileError {
    /// One identity component was empty.
    #[error("native wire profile identity is empty")]
    EmptyIdentity,
    /// A profile limit was zero.
    #[error("native wire profile limit is zero")]
    InvalidLimits,
}
