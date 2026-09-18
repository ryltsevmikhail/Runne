use crate::configured_limits::{
    ConfiguredChatModelLimits, validate_gateway_billing, validate_payg,
};
use crate::{
    ChatCompletionsAccounting, ChatCompletionsBillingMode, ChatCompletionsProfile,
    ChatCompletionsThinkingMode,
};

const REVISION: &str = "operator-configured-chat-v1";

/// Dynamic fixed endpoint family supported by the generic Chat renderer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfiguredChatProvider {
    /// Amazon Bedrock Mantle Chat Completions endpoint.
    AmazonBedrock,
    /// Cloudflare Workers AI OpenAI-compatible endpoint.
    CloudflareWorkersAi,
    /// Cloudflare AI Gateway OpenAI-compatible endpoint.
    CloudflareAiGateway,
    /// NVIDIA NIM OpenAI-compatible endpoint.
    Nvidia,
}

/// Owned endpoint configuration and its usable validated Chat profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredChatProfile {
    provider: ConfiguredChatProvider,
    billing_mode: ChatCompletionsBillingMode,
    profile: ChatCompletionsProfile,
}

/// Configuration failure for dynamic provider-owned endpoint components.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfiguredChatProfileError {
    /// Region, account, gateway, model, or profile component is unsafe.
    #[error("configured Chat Completions component is invalid")]
    InvalidComponent,
    /// No trusted accounting contract was supplied.
    #[error("configured Chat Completions accounting is unavailable")]
    Unpriced,
    /// A configured endpoint used a subscription or invalid PAYG quote.
    #[error("configured Chat Completions billing is unsupported")]
    UnsupportedBilling,
    /// The configured route omitted its model-specific limits.
    #[error("configured Chat Completions model limits are required")]
    MissingLimits,
    /// The Cloudflare Gateway billing route is not explicit.
    #[error("Cloudflare AI Gateway billing mode is invalid")]
    InvalidBillingMode,
    /// The supplied model, wire or billing limits are inconsistent.
    #[error("configured Chat Completions limits are invalid")]
    InvalidLimits,
}

impl ConfiguredChatProfile {
    /// Provider family for selecting transport authentication.
    #[must_use]
    pub const fn provider(&self) -> ConfiguredChatProvider {
        self.provider
    }
    /// Explicit billing route bound into the profile digest.
    #[must_use]
    pub const fn billing_mode(&self) -> ChatCompletionsBillingMode {
        self.billing_mode
    }
    /// Usable profile for `ChatCompletionsRenderer` and the generic effect.
    #[must_use]
    pub const fn profile(&self) -> &ChatCompletionsProfile {
        &self.profile
    }
    /// Consumes the configuration and returns its usable profile.
    #[must_use]
    pub fn into_profile(self) -> ChatCompletionsProfile {
        self.profile
    }
    /// Stable provider identity.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        self.profile.provider_id()
    }
    /// Exact profile identity.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        self.profile.profile_id()
    }
    /// Model sent to the provider.
    #[must_use]
    pub fn model_id(&self) -> &str {
        self.profile.model_id()
    }
    /// Profile model revision.
    #[must_use]
    pub fn model_revision(&self) -> &str {
        self.profile.model_revision()
    }
    /// Owned HTTPS origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        self.profile.origin()
    }
    /// Owned request path.
    #[must_use]
    pub fn path(&self) -> &str {
        self.profile.path()
    }
    /// Content-bound profile digest.
    #[must_use]
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile.profile_digest()
    }
    /// Content-bound pricing digest.
    #[must_use]
    pub const fn pricing_revision_digest(&self) -> [u8; 32] {
        self.profile.pricing_revision_digest()
    }
    /// Explicit PAYG accounting semantics.
    #[must_use]
    pub const fn accounting(&self) -> ChatCompletionsAccounting {
        self.profile.accounting()
    }
    /// Provider-specific thinking encoding.
    #[must_use]
    pub const fn thinking_mode(&self) -> ChatCompletionsThinkingMode {
        self.profile.thinking_mode()
    }
}

#[path = "configured_builders.rs"]
mod builders;

pub use builders::{
    bedrock, bedrock_with_limits, cloudflare_gateway, cloudflare_gateway_with_limits,
    cloudflare_workers, cloudflare_workers_with_limits, nvidia, nvidia_with_limits,
};
