use gocode_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Exact immutable `OpenAI` Responses text profile identity.
pub const OPENAI_RESPONSES_PROFILE_ID: &str = "gocode-openai-responses-text/1";
/// Exact provider request model snapshot.
pub const OPENAI_REQUEST_MODEL: &str = "gpt-5.5-2026-04-23";
/// Provider-neutral model family bound into `ModelRef`.
pub const OPENAI_MODEL_ID: &str = "gpt-5.5";
/// Provider-neutral immutable model revision bound into `ModelRef`.
pub const OPENAI_MODEL_REVISION: &str = "2026-04-23";

const PROFILE_SCHEMA_VERSION: u64 = 1;
const PROFILE_REVISION: u64 = 1;
const PROVIDER_ID: &str = "openai";
const ORIGIN: &str = "https://api.openai.com";
const PATH: &str = "/v1/responses";
const PRICING_REVISION: &str = "openai-gpt-5.5-standard-short-context-2026-07-31/1";
const PRICING_CURRENCY: &str = "USD";
const PRICING_UNIT_TOKENS: u64 = 1_000_000;
const INPUT_MICROS: u64 = 5_000_000;
const CACHED_INPUT_MICROS: u64 = 500_000;
const OUTPUT_MICROS: u64 = 30_000_000;
const LONG_CONTEXT_THRESHOLD_TOKENS: u64 = 272_000;
const MAX_INPUT_ENTRIES: usize = 64;
const MAX_INPUT_ENTRY_BYTES: usize = 65_536;
const MAX_INPUT_BYTES: usize = 262_144;
const MAX_OUTPUT_TOKENS: u32 = 16_384;
const MAX_REQUEST_BYTES: usize = 524_288;
const MAX_PROFILE_BYTES: usize = 16 * 1024;
const PRICING_DIGEST_DOMAIN: &[u8] = b"GOCODE_OPENAI_RESPONSES_TEXT_PRICING_V1\0";
const PROFILE_SOURCE_DIGEST: [u8; 32] = [
    0x48, 0xdd, 0x02, 0x34, 0x57, 0x32, 0xd8, 0xb7, 0x34, 0x9d, 0x09, 0x67, 0xdf, 0xb0, 0xb2, 0xee,
    0x61, 0x81, 0x6b, 0x6a, 0x27, 0xf2, 0xb1, 0x57, 0xde, 0x42, 0x3f, 0x53, 0xd6, 0x62, 0xe9, 0x64,
];

/// Exact-profile validation or pricing failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OpenAiProfileError {
    /// Profile bytes or any exact field differ from the released profile.
    #[error("invalid OpenAI Responses text profile")]
    InvalidProfile,
    /// Usage requires a pricing tier intentionally excluded by this profile.
    #[error("provider usage requires an unsupported pricing tier")]
    UnsupportedPricingTier,
    /// Fixed-point pricing arithmetic exceeded its bound.
    #[error("provider pricing arithmetic overflow")]
    PricingOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    schema_version: u64,
    profile_id: String,
    profile_revision: u64,
    provider_id: String,
    origin: String,
    path: String,
    model: ModelProfile,
    pricing: PricingProfile,
    capabilities: Vec<String>,
    developer_prompt: Value,
    request: RequestProfile,
    limits: LimitsProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelProfile {
    request_id: String,
    model_id: String,
    revision: String,
    aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PricingProfile {
    revision: String,
    currency: String,
    unit_tokens: u64,
    input_micros: u64,
    cached_input_micros: u64,
    output_micros: u64,
    long_context_threshold_tokens: u64,
    long_context_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestProfile {
    reasoning_effort: String,
    tools: Vec<Value>,
    tool_choice: String,
    background: bool,
    store: bool,
    stream: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct LimitsProfile {
    max_input_entries: usize,
    max_input_entry_bytes: usize,
    max_input_bytes: usize,
    max_output_tokens: u32,
    max_request_bytes: usize,
}

/// Validated exact `OpenAI` Responses text profile plus its source digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiResponsesTextProfile {
    source_digest: [u8; 32],
    pricing_digest: [u8; 32],
    raw: RawProfile,
}

impl OpenAiResponsesTextProfile {
    /// Parses one bounded profile and rejects every non-exact field.
    ///
    /// # Errors
    ///
    /// Returns [`OpenAiProfileError::InvalidProfile`] when the bytes are
    /// malformed, unbounded, or differ from the immutable profile.
    pub fn from_json(bytes: &[u8]) -> Result<Self, OpenAiProfileError> {
        if bytes.is_empty() || bytes.len() > MAX_PROFILE_BYTES {
            return Err(OpenAiProfileError::InvalidProfile);
        }
        let raw: RawProfile =
            serde_json::from_slice(bytes).map_err(|_| OpenAiProfileError::InvalidProfile)?;
        validate_exact(&raw)?;
        let source_digest: [u8; 32] = Sha256::digest(bytes).into();
        if source_digest != PROFILE_SOURCE_DIGEST {
            return Err(OpenAiProfileError::InvalidProfile);
        }
        let pricing_digest = pricing_digest(&raw.pricing)?;
        Ok(Self {
            source_digest,
            pricing_digest,
            raw,
        })
    }

    /// Returns the exact versioned adapter profile identity.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.raw.profile_id
    }

    /// Returns the exact provider identity.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.raw.provider_id
    }

    /// Returns the exact HTTPS origin without a path.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.raw.origin
    }

    /// Returns the exact Responses API path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.raw.path
    }

    /// Returns the exact provider request model snapshot.
    #[must_use]
    pub fn request_model(&self) -> &str {
        &self.raw.model.request_id
    }

    /// Returns the provider-neutral model identity.
    #[must_use]
    pub fn model_id(&self) -> &str {
        &self.raw.model.model_id
    }

    /// Returns the provider-neutral immutable model revision.
    #[must_use]
    pub fn model_revision(&self) -> &str {
        &self.raw.model.revision
    }

    /// Returns the SHA-256 digest of the exact distributed profile bytes.
    #[must_use]
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.source_digest
    }

    /// Returns the domain-separated immutable pricing contract digest.
    #[must_use]
    pub const fn pricing_revision_digest(&self) -> [u8; 32] {
        self.pricing_digest
    }

    /// Returns the exact fixed-point pricing currency.
    #[must_use]
    pub fn currency(&self) -> &str {
        &self.raw.pricing.currency
    }

    /// Returns the maximum accepted committed context entries.
    #[must_use]
    pub const fn max_input_entries(&self) -> usize {
        self.raw.limits.max_input_entries
    }

    /// Returns the maximum bytes accepted for one committed text entry.
    #[must_use]
    pub const fn max_input_entry_bytes(&self) -> usize {
        self.raw.limits.max_input_entry_bytes
    }

    /// Returns the maximum aggregate committed text bytes.
    #[must_use]
    pub const fn max_input_bytes(&self) -> usize {
        self.raw.limits.max_input_bytes
    }

    /// Returns the GOCODE output-token ceiling for this profile.
    #[must_use]
    pub const fn max_output_tokens(&self) -> u32 {
        self.raw.limits.max_output_tokens
    }

    /// Returns the maximum serialized credential-free request bytes.
    #[must_use]
    pub const fn max_request_bytes(&self) -> usize {
        self.raw.limits.max_request_bytes
    }

    /// Builds the only provider-call extension accepted by the renderer.
    #[must_use]
    pub fn binding_extension(&self) -> Value {
        json!({
            "profile_id": self.profile_id(),
            "profile_digest": hex::encode(self.profile_digest()),
            "pricing_revision_digest": hex::encode(self.pricing_revision_digest()),
        })
    }

    /// Prices short-context standard usage with checked fixed-point arithmetic.
    ///
    /// Each category rounds up independently to one micro-unit. Reasoning
    /// tokens are already included in provider `output_tokens`.
    ///
    /// # Errors
    ///
    /// Returns [`OpenAiProfileError::UnsupportedPricingTier`] for long-context
    /// usage and [`OpenAiProfileError::PricingOverflow`] when checked
    /// fixed-point arithmetic cannot represent the result.
    pub fn price_usage_micros(&self, usage: ProviderUsage) -> Result<u64, OpenAiProfileError> {
        if usage.input_tokens() > self.raw.pricing.long_context_threshold_tokens {
            return Err(OpenAiProfileError::UnsupportedPricingTier);
        }
        let uncached = usage
            .input_tokens()
            .checked_sub(usage.cached_input_tokens())
            .ok_or(OpenAiProfileError::PricingOverflow)?;
        let input = prorated_micros(
            uncached,
            self.raw.pricing.input_micros,
            self.raw.pricing.unit_tokens,
        )?;
        let cached = prorated_micros(
            usage.cached_input_tokens(),
            self.raw.pricing.cached_input_micros,
            self.raw.pricing.unit_tokens,
        )?;
        let output = prorated_micros(
            usage.output_tokens(),
            self.raw.pricing.output_micros,
            self.raw.pricing.unit_tokens,
        )?;
        input
            .checked_add(cached)
            .and_then(|subtotal| subtotal.checked_add(output))
            .ok_or(OpenAiProfileError::PricingOverflow)
    }
}

impl ProviderTerminalPricing for OpenAiResponsesTextProfile {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        if pricing_revision_digest != &self.pricing_revision_digest()
            || profile_digest != &self.profile_digest()
        {
            return Err(ProviderTerminalPricingError::Unavailable);
        }
        let charge_micros = self
            .price_usage_micros(usage)
            .map_err(|error| match error {
                OpenAiProfileError::UnsupportedPricingTier | OpenAiProfileError::InvalidProfile => {
                    ProviderTerminalPricingError::Unavailable
                }
                OpenAiProfileError::PricingOverflow => ProviderTerminalPricingError::InvalidQuote,
            })?;
        ProviderPricedUsage::new(charge_micros, self.currency().to_owned())
    }
}

fn validate_exact(profile: &RawProfile) -> Result<(), OpenAiProfileError> {
    let exact = profile.schema_version == PROFILE_SCHEMA_VERSION
        && profile.profile_id == OPENAI_RESPONSES_PROFILE_ID
        && profile.profile_revision == PROFILE_REVISION
        && profile.provider_id == PROVIDER_ID
        && profile.origin == ORIGIN
        && profile.path == PATH
        && profile.model.request_id == OPENAI_REQUEST_MODEL
        && profile.model.model_id == OPENAI_MODEL_ID
        && profile.model.revision == OPENAI_MODEL_REVISION
        && profile.model.aliases.is_empty()
        && profile.pricing.revision == PRICING_REVISION
        && profile.pricing.currency == PRICING_CURRENCY
        && profile.pricing.unit_tokens == PRICING_UNIT_TOKENS
        && profile.pricing.input_micros == INPUT_MICROS
        && profile.pricing.cached_input_micros == CACHED_INPUT_MICROS
        && profile.pricing.output_micros == OUTPUT_MICROS
        && profile.pricing.long_context_threshold_tokens == LONG_CONTEXT_THRESHOLD_TOKENS
        && !profile.pricing.long_context_enabled
        && profile.capabilities == ["streaming"]
        && profile.developer_prompt.is_null()
        && profile.request.reasoning_effort == "none"
        && profile.request.tools.is_empty()
        && profile.request.tool_choice == "none"
        && !profile.request.background
        && !profile.request.store
        && profile.request.stream
        && profile.limits.max_input_entries == MAX_INPUT_ENTRIES
        && profile.limits.max_input_entry_bytes == MAX_INPUT_ENTRY_BYTES
        && profile.limits.max_input_bytes == MAX_INPUT_BYTES
        && profile.limits.max_output_tokens == MAX_OUTPUT_TOKENS
        && profile.limits.max_request_bytes == MAX_REQUEST_BYTES;
    if !exact {
        return Err(OpenAiProfileError::InvalidProfile);
    }
    Ok(())
}

fn pricing_digest(profile: &PricingProfile) -> Result<[u8; 32], OpenAiProfileError> {
    let bytes = serde_json::to_vec(profile).map_err(|_| OpenAiProfileError::InvalidProfile)?;
    let length = u64::try_from(bytes.len()).map_err(|_| OpenAiProfileError::InvalidProfile)?;
    let mut hasher = Sha256::new();
    hasher.update(PRICING_DIGEST_DOMAIN);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

fn prorated_micros(
    tokens: u64,
    rate_micros: u64,
    unit_tokens: u64,
) -> Result<u64, OpenAiProfileError> {
    let numerator = tokens
        .checked_mul(rate_micros)
        .ok_or(OpenAiProfileError::PricingOverflow)?;
    let rounded = numerator
        .checked_add(unit_tokens - 1)
        .ok_or(OpenAiProfileError::PricingOverflow)?;
    Ok(rounded / unit_tokens)
}
