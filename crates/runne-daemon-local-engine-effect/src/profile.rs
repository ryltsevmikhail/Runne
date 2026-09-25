//! Deterministic Local Engine text profile: credential-free, zero
//! monetary pricing, bounded inputs/outputs. Profile bytes are the
//! contract; the digest in `runne-api` must stay in sync.

use runne_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
    TextProviderProfile,
};

pub const LOCAL_ENGINE_PROFILE_ID: &str = "gocode-local-engine-text/1";
pub const LOCAL_ENGINE_PROFILE_REVISION: &str = "1";
/// ISO 4217 "no currency" code: local execution carries no charge.
pub const LOCAL_ENGINE_CURRENCY: &str = "XXX";
pub const LOCAL_ENGINE_ZERO_PRICE_MICROS: u64 = 0;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_INPUT_ENTRIES: usize = 64;
const MAX_INPUT_ENTRY_BYTES: usize = 32 * 1024;
const MAX_OUTPUT_TOKENS: u32 = 1024;
const MAX_REQUEST_BYTES: usize = 96 * 1024;

/// Validated immutable Local Engine text profile.
#[derive(Debug, Clone)]
pub struct LocalEngineTextProfile {
    bytes: Vec<u8>,
}

impl LocalEngineTextProfile {
    /// Validates and binds the exact distributed profile bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, LocalEngineProfileError> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| LocalEngineProfileError)?;
        let id = value
            .get("profileId")
            .and_then(|v| v.as_str())
            .ok_or(LocalEngineProfileError)?;
        if id != LOCAL_ENGINE_PROFILE_ID {
            return Err(LocalEngineProfileError);
        }
        let max_output = value
            .get("maxOutputTokens")
            .and_then(|v| v.as_u64())
            .ok_or(LocalEngineProfileError)?;
        if max_output != u64::from(MAX_OUTPUT_TOKENS) {
            return Err(LocalEngineProfileError);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalEngineProfileError;

impl std::fmt::Display for LocalEngineProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("local engine profile bytes invalid")
    }
}

impl std::error::Error for LocalEngineProfileError {}

impl TextProviderProfile for LocalEngineTextProfile {
    fn profile_id(&self) -> &str {
        LOCAL_ENGINE_PROFILE_ID
    }

    fn profile_digest(&self) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(&self.bytes).into()
    }

    fn pricing_revision_digest(&self) -> [u8; 32] {
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, b"local-engine-zero-pricing/v1");
        sha2::Digest::finalize(h).into()
    }

    fn currency(&self) -> &str {
        LOCAL_ENGINE_CURRENCY
    }

    fn max_input_bytes(&self) -> usize {
        MAX_INPUT_BYTES
    }

    fn max_input_entries(&self) -> usize {
        MAX_INPUT_ENTRIES
    }

    fn max_input_entry_bytes(&self) -> usize {
        MAX_INPUT_ENTRY_BYTES
    }

    fn max_output_tokens(&self) -> u32 {
        MAX_OUTPUT_TOKENS
    }

    fn max_request_bytes(&self) -> usize {
        MAX_REQUEST_BYTES
    }

    fn price_usage_micros(
        &self,
        _usage: ProviderUsage,
    ) -> Result<u64, ProviderTerminalPricingError> {
        Ok(LOCAL_ENGINE_ZERO_PRICE_MICROS)
    }
}

impl ProviderTerminalPricing for LocalEngineTextProfile {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        _effect_started_at: i64,
        _usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        // Zero monetary pricing by contract; digests must be the exact
        // admitted ones so downstream pricing checks stay coherent.
        if pricing_revision_digest != &self.pricing_revision_digest()
            || profile_digest != &self.profile_digest()
        {
            return Err(ProviderTerminalPricingError::Unavailable);
        }
        ProviderPricedUsage::new(
            LOCAL_ENGINE_ZERO_PRICE_MICROS,
            LOCAL_ENGINE_CURRENCY.to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_engine_terminal_pricing_is_zero_for_any_effect_time() {
        let profile = LocalEngineTextProfile::from_json(
            br#"{"profileId":"gocode-local-engine-text/1","maxOutputTokens":1024}"#,
        )
        .unwrap();
        let pricing_digest = profile.pricing_revision_digest();
        let profile_digest = profile.profile_digest();

        for effect_started_at in [0, 1_789_948_800, i64::MAX] {
            let priced = profile
                .price_terminal_usage(
                    &pricing_digest,
                    &profile_digest,
                    effect_started_at,
                    ProviderUsage::new(0, 0, 0, 0).unwrap(),
                )
                .unwrap();
            assert_eq!(priced.charge_micros(), 0);
            assert_eq!(priced.currency(), LOCAL_ENGINE_CURRENCY);
        }
    }
}
