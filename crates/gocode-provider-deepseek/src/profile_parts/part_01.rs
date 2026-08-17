use gocode_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Exact immutable `DeepSeek` Responses text profile identity.
pub const DEEPSEEK_RESPONSES_PROFILE_ID: &str = "gocode-deepseek-responses-text/1";
/// Exact provider request model snapshot.
pub const DEEPSEEK_REQUEST_MODEL: &str = "deepseek-chat";
/// Exact Standard processing tier requested and required in response evidence.
pub const DEEPSEEK_SERVICE_TIER: &str = "default";
/// Provider-neutral model family bound into `ModelRef`.
pub const DEEPSEEK_MODEL_ID: &str = "deepseek-chat";
/// Provider-neutral immutable model revision bound into `ModelRef`.
pub const DEEPSEEK_MODEL_REVISION: &str = "2026-08-16";

const PROFILE_SCHEMA_VERSION: u64 = 1;
const PROFILE_REVISION: u64 = 1;
const PROVIDER_ID: &str = "deepseek";
const ORIGIN: &str = "https://api.deepseek.com";
const PATH: &str = "/v1/responses";
const PRICING_REVISION: &str = "deepseek-chat-base-2026-08-16/1";
const PRICING_CURRENCY: &str = "USD";
const PRICING_UNIT_TOKENS: u64 = 1_000_000;
const INPUT_MICROS: u64 = 270_000;
const CACHED_INPUT_MICROS: u64 = 28_000;
const OUTPUT_MICROS: u64 = 1_100_000;
const LONG_CONTEXT_THRESHOLD_TOKENS: u64 = 1_000_000;
const MAX_INPUT_ENTRIES: usize = 64;
const MAX_INPUT_ENTRY_BYTES: usize = 65_536;
const MAX_INPUT_BYTES: usize = 262_144;
const MAX_OUTPUT_TOKENS: u32 = 16_384;
const MAX_REQUEST_BYTES: usize = 524_288;
const MAX_PROFILE_BYTES: usize = 16 * 1024;
const PRICING_DIGEST_DOMAIN: &[u8] = b"GOCODE_DEEPSEEK_RESPONSES_TEXT_PRICING_V1\0";
const PROFILE_SOURCE_DIGEST: [u8; 32] = [
    0x25, 0x67, 0x0f, 0xfe, 0x78, 0xdb, 0xc7, 0xef, 0x4d, 0xb8, 0x91, 0x13, 0x56, 0xd9, 0xeb, 0x4e,
    0x27, 0x41, 0x67, 0xff, 0x9e, 0xed, 0x0a, 0x7c, 0xc9, 0xb5, 0xe6, 0x6e, 0x40, 0x85, 0xd8, 0x53,
];

/// Exact-profile validation or pricing failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DeepSeekProfileError {
    /// Profile bytes or any exact field differ from the released profile.
    #[error("invalid DeepSeek Responses text profile")]
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
    service_tier: String,
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

/// Validated exact `DeepSeek` Responses text profile plus its source digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepSeekResponsesTextProfile {
    source_digest: [u8; 32],
    pricing_digest: [u8; 32],
    raw: RawProfile,
}
