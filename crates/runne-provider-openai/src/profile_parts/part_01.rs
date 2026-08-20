use runne_provider::{
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
/// Exact Standard processing tier requested and required in response evidence.
pub const OPENAI_SERVICE_TIER: &str = "default";
/// Provider-neutral model family bound into `ModelRef`.
pub const OPENAI_MODEL_ID: &str = "gpt-5.5";
/// Provider-neutral immutable model revision bound into `ModelRef`.
pub const OPENAI_MODEL_REVISION: &str = "2026-04-23";

const PROFILE_SCHEMA_VERSION: u64 = 1;
const PROFILE_REVISION: u64 = 2;
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
    0xd3, 0xe2, 0x09, 0x34, 0x77, 0x5d, 0x9d, 0x97, 0x03, 0x50, 0xd1, 0x6b, 0x78, 0xa1, 0x73, 0x98,
    0x85, 0xc0, 0x8d, 0xd5, 0xd3, 0xe4, 0x7b, 0x93, 0x07, 0x23, 0x3d, 0x4d, 0xd0, 0xfb, 0xed, 0x80,
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

/// Validated exact `OpenAI` Responses text profile plus its source digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiResponsesTextProfile {
    source_digest: [u8; 32],
    pricing_digest: [u8; 32],
    raw: RawProfile,
}
