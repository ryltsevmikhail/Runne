mod core;

use serde_json::Value;

use core::ProfileCore;
pub use core::{NativeAccounting, NativeWireProfileError, WireLimits};

#[path = "profile_contract.rs"]
mod contract;
#[path = "profile_pricing.rs"]
mod pricing;

/// A composition-friendly native profile without inventing provider pricing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeWireProfile {
    /// Anthropic Messages-compatible text profile.
    Anthropic(AnthropicMessagesProfile),
    /// Gemini Generate Content-compatible text profile.
    Gemini(GeminiProfile),
}

impl NativeWireProfile {
    /// Returns the provider identity admitted by the profile.
    pub fn provider_id(&self) -> &str {
        match self {
            Self::Anthropic(profile) => profile.provider_id(),
            Self::Gemini(profile) => profile.provider_id(),
        }
    }
    /// Returns the exact model identity admitted by the profile.
    pub fn model_id(&self) -> &str {
        match self {
            Self::Anthropic(profile) => profile.model_id(),
            Self::Gemini(profile) => profile.model_id(),
        }
    }
    /// Returns the exact model revision admitted by the profile.
    pub fn model_revision(&self) -> &str {
        match self {
            Self::Anthropic(profile) => profile.model_revision(),
            Self::Gemini(profile) => profile.model_revision(),
        }
    }
    /// Returns the immutable profile digest.
    pub fn profile_digest(&self) -> [u8; 32] {
        match self {
            Self::Anthropic(profile) => profile.profile_digest(),
            Self::Gemini(profile) => profile.profile_digest(),
        }
    }
    /// Returns the response/request limits.
    pub fn limits(&self) -> WireLimits {
        match self {
            Self::Anthropic(profile) => profile.limits(),
            Self::Gemini(profile) => profile.limits(),
        }
    }
    /// Returns the immutable accounting contract.
    pub fn accounting(&self) -> NativeAccounting {
        match self {
            Self::Anthropic(profile) => profile.accounting(),
            Self::Gemini(profile) => profile.accounting(),
        }
    }
}

/// Immutable admitted Anthropic Messages text profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnthropicMessagesProfile(ProfileCore);

impl AnthropicMessagesProfile {
    /// Creates a profile whose endpoint is always `/v1/messages`.
    pub fn new(
        provider: &str,
        profile: &str,
        model: &str,
        revision: &str,
        profile_digest: [u8; 32],
        pricing_digest: [u8; 32],
        limits: WireLimits,
    ) -> Result<Self, NativeWireProfileError> {
        Ok(Self(ProfileCore::new(
            provider,
            profile,
            model,
            revision,
            profile_digest,
            pricing_digest,
            limits,
        )?))
    }
    /// Creates an Anthropic profile with an explicit accounting contract.
    #[allow(
        clippy::too_many_arguments,
        reason = "public constructor preserves the stable native profile API"
    )]
    pub fn new_with_accounting(
        provider: &str,
        profile: &str,
        model: &str,
        revision: &str,
        profile_digest: [u8; 32],
        pricing_digest: [u8; 32],
        limits: WireLimits,
        accounting: NativeAccounting,
    ) -> Result<Self, NativeWireProfileError> {
        Ok(Self(ProfileCore::new_with_accounting(
            provider,
            profile,
            model,
            revision,
            profile_digest,
            pricing_digest,
            limits,
            accounting,
        )?))
    }
    /// Adds one explicitly trusted provider-reported model-version alias.
    pub fn with_model_version_alias(mut self, alias: &str) -> Result<Self, NativeWireProfileError> {
        self.0 = self.0.clone().with_model_version_alias(alias)?;
        Ok(self)
    }
    /// Returns the provider identity.
    pub fn provider_id(&self) -> &str {
        self.0.provider_id()
    }
    /// Returns the exact profile identity.
    pub fn profile_id(&self) -> &str {
        self.0.profile_id()
    }
    /// Returns the request model identity.
    pub fn model_id(&self) -> &str {
        self.0.model_id()
    }
    /// Returns the model revision.
    pub fn model_revision(&self) -> &str {
        self.0.revision()
    }
    /// Returns the explicitly trusted provider-reported model alias, if any.
    pub fn model_version_alias(&self) -> Option<&str> {
        self.0.model_version_alias()
    }
    /// Returns the profile digest.
    pub fn profile_digest(&self) -> [u8; 32] {
        self.0.profile_digest()
    }
    /// Returns the pricing revision digest.
    pub fn pricing_revision_digest(&self) -> [u8; 32] {
        self.0.pricing_digest()
    }
    /// Returns the exact extension admitted by this profile.
    pub fn binding_extension(&self) -> Value {
        self.0.extension()
    }
    /// Returns profile limits.
    pub fn limits(&self) -> WireLimits {
        self.0.limits()
    }
    /// Returns the immutable accounting contract.
    pub fn accounting(&self) -> NativeAccounting {
        self.0.accounting()
    }
}

/// Immutable admitted Gemini Generate Content text profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiProfile(ProfileCore);

impl GeminiProfile {
    /// Creates a profile whose method is always `streamGenerateContent`.
    pub fn new(
        provider: &str,
        profile: &str,
        model: &str,
        revision: &str,
        profile_digest: [u8; 32],
        pricing_digest: [u8; 32],
        limits: WireLimits,
    ) -> Result<Self, NativeWireProfileError> {
        Ok(Self(ProfileCore::new(
            provider,
            profile,
            model,
            revision,
            profile_digest,
            pricing_digest,
            limits,
        )?))
    }
    /// Creates a Gemini profile with an explicit accounting contract.
    #[allow(
        clippy::too_many_arguments,
        reason = "public constructor preserves the stable native profile API"
    )]
    pub fn new_with_accounting(
        provider: &str,
        profile: &str,
        model: &str,
        revision: &str,
        profile_digest: [u8; 32],
        pricing_digest: [u8; 32],
        limits: WireLimits,
        accounting: NativeAccounting,
    ) -> Result<Self, NativeWireProfileError> {
        Ok(Self(ProfileCore::new_with_accounting(
            provider,
            profile,
            model,
            revision,
            profile_digest,
            pricing_digest,
            limits,
            accounting,
        )?))
    }
    /// Adds one explicitly trusted provider-reported model-version alias.
    pub fn with_model_version_alias(mut self, alias: &str) -> Result<Self, NativeWireProfileError> {
        self.0 = self.0.clone().with_model_version_alias(alias)?;
        Ok(self)
    }
    /// Returns the provider identity.
    pub fn provider_id(&self) -> &str {
        self.0.provider_id()
    }
    /// Returns the exact profile identity.
    pub fn profile_id(&self) -> &str {
        self.0.profile_id()
    }
    /// Returns the request model identity.
    pub fn model_id(&self) -> &str {
        self.0.model_id()
    }
    /// Returns the model revision.
    pub fn model_revision(&self) -> &str {
        self.0.revision()
    }
    /// Returns the explicitly trusted provider-reported model alias, if any.
    pub fn model_version_alias(&self) -> Option<&str> {
        self.0.model_version_alias()
    }
    /// Returns the profile digest.
    pub fn profile_digest(&self) -> [u8; 32] {
        self.0.profile_digest()
    }
    /// Returns the pricing revision digest.
    pub fn pricing_revision_digest(&self) -> [u8; 32] {
        self.0.pricing_digest()
    }
    /// Returns the exact extension admitted by this profile.
    pub fn binding_extension(&self) -> Value {
        self.0.extension()
    }
    /// Returns profile limits.
    pub fn limits(&self) -> WireLimits {
        self.0.limits()
    }
    /// Returns the immutable accounting contract.
    pub fn accounting(&self) -> NativeAccounting {
        self.0.accounting()
    }
}
