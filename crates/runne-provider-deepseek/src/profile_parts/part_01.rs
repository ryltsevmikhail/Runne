use runne_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Exact immutable `DeepSeek` Responses text profile identity.
pub const DEEPSEEK_RESPONSES_PROFILE_ID: &str = "runne-deepseek-responses-text/1";
/// Exact provider request model snapshot.
pub const DEEPSEEK_REQUEST_MODEL: &str = "deepseek-flash";
/// Legacy pinned Standard tier; the documented `/responses` contract neither
/// sends nor validates `service_tier`. Retained for workspace compatibility.
pub const DEEPSEEK_SERVICE_TIER: &str = "default";
/// Provider-neutral model family bound into `ModelRef`.
pub const DEEPSEEK_MODEL_ID: &str = "deepseek-flash";
/// Provider-neutral immutable model revision bound into `ModelRef`.
pub const DEEPSEEK_MODEL_REVISION: &str = "2026-09-21";

const PROFILE_SCHEMA_VERSION: u64 = 1;
const PROFILE_REVISION: u64 = 2;
const PROVIDER_ID: &str = "deepseek";
const ORIGIN: &str = "https://api.deepseek.com";
const PATH: &str = "/responses";
const PRICING_REVISION: &str = "deepseek-flash-peak-2026-09-21/1";
const PRICING_CURRENCY: &str = "USD";
const PRICING_UNIT_TOKENS: u64 = 1_000_000;
const INPUT_MICROS: u64 = 300_000;
const CACHED_INPUT_MICROS: u64 = 6_000;
const OUTPUT_MICROS: u64 = 1_200_000;
const LONG_CONTEXT_THRESHOLD_TOKENS: u64 = 1_000_000;
const MAX_INPUT_ENTRIES: usize = 64;
const MAX_INPUT_ENTRY_BYTES: usize = 65_536;
const MAX_INPUT_BYTES: usize = 262_144;
const MAX_OUTPUT_TOKENS: u32 = 16_384;
const MAX_REQUEST_BYTES: usize = 524_288;
const MAX_PROFILE_BYTES: usize = 16 * 1024;
const PRICING_DIGEST_DOMAIN: &[u8] = b"GOCODE_DEEPSEEK_RESPONSES_TEXT_PRICING_V1\0";
const PROFILE_SOURCE_DIGEST: [u8; 32] = [
    0x01, 0x12, 0xc4, 0xb6, 0xce, 0x64, 0x73, 0x98, 0x10, 0xbb, 0x79, 0x80, 0x2e, 0xbb, 0x5a, 0xe6,
    0xfd, 0x8a, 0xc5, 0x63, 0xd1, 0xd1, 0x39, 0x7a, 0xc5, 0x1f, 0x07, 0xa1, 0x90, 0x53, 0x81, 0x95,
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
    /// The pinned pricing snapshot is not effective at the effect timestamp.
    #[error("provider pricing snapshot is unavailable at effect start")]
    PricingUnavailable,
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
    effective_from_unix_seconds: i64,
    currency: String,
    unit_tokens: u64,
    peak_input_micros: u64,
    peak_cached_input_micros: u64,
    peak_output_micros: u64,
    off_peak_input_micros: u64,
    off_peak_cached_input_micros: u64,
    off_peak_output_micros: u64,
    peak_iso_weekdays: Vec<u8>,
    peak_windows_utc: Vec<[u16; 2]>,
    long_context_threshold_tokens: u64,
    long_context_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestProfile {
    reasoning_effort: String,
    tools: Vec<Value>,
    tool_choice: String,
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
