use runne_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
    TextProviderProfile,
};

use super::{RadiusAccounting, RadiusConfigError, RadiusCost, RadiusProfile};

pub(super) fn rates(cost: &RadiusCost) -> Result<[u64; 4], RadiusConfigError> {
    Ok([
        rate(cost.input)?,
        rate(cost.output)?,
        rate(cost.cache_read)?,
        rate(cost.cache_write)?,
    ])
}

fn rate(value: f64) -> Result<u64, RadiusConfigError> {
    // Prices arrive as f64; above 2^53-1 micros an integer conversion loses information.
    const MAX_EXACT_MICROS: f64 = 9_007_199_254_740_991.0;
    let scaled = value * 1_000_000.0;
    if !scaled.is_finite() || !(0.0..=MAX_EXACT_MICROS).contains(&scaled) {
        return Err(RadiusConfigError::InvalidModel);
    }
    let rounded = scaled.round();
    if (rounded - scaled).abs() > 0.000_001 {
        return Err(RadiusConfigError::InvalidModel);
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "finite nonnegative rounded value is bounded by MAX_EXACT_MICROS"
    )]
    let micros = rounded as u64;
    Ok(micros)
}

impl RadiusProfile {
    /// Returns the immutable input rate in micro-USD per million tokens.
    pub const fn input_micros_per_million(&self) -> u64 {
        self.input_micros_per_million
    }
    /// Returns the immutable output rate in micro-USD per million tokens.
    pub const fn output_micros_per_million(&self) -> u64 {
        self.output_micros_per_million
    }
    /// Returns the immutable cached-input rate in micro-USD per million tokens.
    pub const fn cached_input_micros_per_million(&self) -> u64 {
        self.cached_input_micros_per_million
    }
    /// Returns the immutable cache-write rate in micro-USD per million tokens.
    pub const fn cache_write_micros_per_million(&self) -> u64 {
        self.cache_write_micros_per_million
    }
}

impl ProviderTerminalPricing for RadiusProfile {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        if pricing_revision_digest != &self.catalog_digest()
            || profile_digest != &self.profile_digest()
        {
            return Err(ProviderTerminalPricingError::Unavailable);
        }
        if self.accounting() == RadiusAccounting::SubscriptionQuota {
            return ProviderPricedUsage::new(0, "XXX".to_owned());
        }
        let uncached = usage
            .input_tokens()
            .checked_sub(usage.cached_input_tokens())
            .ok_or(ProviderTerminalPricingError::InvalidQuote)?;
        let input = prorated(uncached, self.input_micros_per_million())?;
        let cached = prorated(
            usage.cached_input_tokens(),
            self.cached_input_micros_per_million(),
        )?;
        let output = prorated(usage.output_tokens(), self.output_micros_per_million())?;
        let charge = input
            .checked_add(cached)
            .and_then(|value| value.checked_add(output))
            .ok_or(ProviderTerminalPricingError::InvalidQuote)?;
        ProviderPricedUsage::new(charge, "USD".to_owned())
    }
}

impl TextProviderProfile for RadiusProfile {
    fn profile_id(&self) -> &'static str {
        "gocode-radius-text/dynamic/1"
    }
    fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest()
    }
    fn pricing_revision_digest(&self) -> [u8; 32] {
        self.catalog_digest()
    }
    fn currency(&self) -> &str {
        match self.accounting() {
            RadiusAccounting::SubscriptionQuota => "XXX",
            RadiusAccounting::Payg => "USD",
        }
    }
    fn max_input_bytes(&self) -> usize {
        self.max_input_bytes()
    }
    fn max_input_entries(&self) -> usize {
        64
    }
    fn max_input_entry_bytes(&self) -> usize {
        262_144
    }
    fn max_output_tokens(&self) -> u32 {
        self.max_tokens()
    }
    fn max_request_bytes(&self) -> usize {
        8 * 1024 * 1024
    }
    fn price_usage_micros(
        &self,
        usage: ProviderUsage,
    ) -> Result<u64, ProviderTerminalPricingError> {
        self.price_terminal_usage(&self.catalog_digest(), &self.profile_digest(), usage)
            .map(|quote| quote.charge_micros())
    }

    fn call_binding_extension(&self) -> serde_json::Value {
        serde_json::json!({
            "radius_catalog_digest": hex::encode(self.catalog_digest()),
            "radius_profile_digest": hex::encode(self.profile_digest()),
            "radius_model_id": self.model_id(),
        })
    }
}

fn prorated(tokens: u64, micros_per_million: u64) -> Result<u64, ProviderTerminalPricingError> {
    if tokens == 0 || micros_per_million == 0 {
        return Ok(0);
    }
    tokens
        .checked_mul(micros_per_million)
        .and_then(|value| value.checked_add(999_999))
        .map(|value| value / 1_000_000)
        .ok_or(ProviderTerminalPricingError::InvalidQuote)
}
