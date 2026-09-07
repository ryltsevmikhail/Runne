//! Deterministic resource estimation (Plan Task 12): a pure function
//! over the admitted manifest, the backend profile and the request.
//! All dimensions are finite, arithmetic is overflow-checked, monetary
//! pricing is immutably zero, and missing limits refuse instead of
//! defaulting to infinity.

use crate::error::ProviderError;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    /// Checked arithmetic overflow while deriving the quote.
    Overflow,
    /// Manifest/profile lacks a limit the estimator refuses to invent.
    MissingLimits(&'static str),
    /// The request cannot fit the profile/manifest envelope.
    InsufficientRam,
    InsufficientContext,
    InsufficientTime,
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => write!(f, "resource arithmetic overflow"),
            Self::MissingLimits(k) => write!(f, "missing limit: {k}"),
            Self::InsufficientRam => write!(f, "insufficient RAM for the quote"),
            Self::InsufficientContext => write!(f, "request exceeds context capacity"),
            Self::InsufficientTime => write!(f, "request exceeds active-time budget"),
        }
    }
}

impl std::error::Error for ResourceError {}

impl From<ResourceError> for ProviderError {
    fn from(e: ResourceError) -> Self {
        ProviderError::Resource(e)
    }
}

/// Inputs the estimator reads (all admitted, digest-bound upstream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstimateInputs {
    /// Exact artifact byte length from the installation.
    pub artifact_bytes: u64,
    /// Context capacity from the manifest capabilities.
    pub context_max_tokens: u64,
    /// Per-token working-set factor of the profile (bytes/token),
    /// bounded and deterministic.
    pub bytes_per_token: u64,
    /// Requested prompt tokens (rendered estimate, digest-bound).
    pub prompt_tokens: u64,
    /// Requested output cap.
    pub max_output_tokens: u64,
    /// Active-time budget of the profile.
    pub active_time_budget_ms: u64,
}

/// The immutable quote: every dimension finite, money zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalResourceQuote {
    pub prompt_tokens: u64,
    pub output_tokens: u64,
    pub context_tokens: u64,
    pub ram_bytes: u64,
    /// CPU profile: always zero (Metal stays BackendUnavailable).
    pub accelerator_bytes: u64,
    pub active_time_ms: u64,
    pub process_starts: u32,
    pub concurrency: u32,
    /// Immutable zero monetary pricing (local execution has no meter).
    pub price_micro_units: u128,
}

/// Deterministic quote; `Err` on overflow or envelope violations. No
/// allocation from untrusted counts: every product is checked.
pub fn quote(inputs: &EstimateInputs) -> Result<LocalResourceQuote, ResourceError> {
    if inputs.bytes_per_token == 0 || inputs.context_max_tokens == 0 {
        return Err(ResourceError::MissingLimits("bytes_per_token/context"));
    }
    if inputs.prompt_tokens > inputs.context_max_tokens {
        return Err(ResourceError::InsufficientContext);
    }
    let output_tokens = inputs.max_output_tokens.min(
        inputs
            .context_max_tokens
            .saturating_sub(inputs.prompt_tokens),
    );
    let context_tokens = inputs
        .prompt_tokens
        .checked_add(output_tokens)
        .ok_or(ResourceError::Overflow)?;
    // Working set: artifact + context working memory + 25% headroom,
    // floored at one GiB (bounded default, recorded as policy).
    let working = context_tokens
        .checked_mul(inputs.bytes_per_token)
        .ok_or(ResourceError::Overflow)?;
    let artifact = inputs
        .artifact_bytes
        .checked_mul(2)
        .ok_or(ResourceError::Overflow)?;
    let ram = working
        .checked_add(artifact)
        .ok_or(ResourceError::Overflow)?
        .checked_mul(5)
        .and_then(|v| v.checked_div(4))
        .ok_or(ResourceError::Overflow)?
        .max(1024 * 1024 * 1024);
    // Active time scales with output under a deterministic per-token
    // cost; exceeding the budget refuses instead of silently extending.
    const ACTIVE_TIME_MS_PER_TOKEN: u64 = 20;
    let needed_ms = output_tokens
        .checked_mul(ACTIVE_TIME_MS_PER_TOKEN)
        .ok_or(ResourceError::Overflow)?;
    if inputs.active_time_budget_ms == 0 {
        return Err(ResourceError::MissingLimits("active_time"));
    }
    if needed_ms > inputs.active_time_budget_ms {
        return Err(ResourceError::InsufficientTime);
    }
    Ok(LocalResourceQuote {
        prompt_tokens: inputs.prompt_tokens,
        output_tokens,
        context_tokens,
        ram_bytes: ram,
        accelerator_bytes: 0,
        active_time_ms: needed_ms.max(1),
        process_starts: 1,
        concurrency: 1,
        price_micro_units: 0,
    })
}
