use chrono::{DateTime, NaiveDate, Utc};

impl DeepSeekResponsesTextProfile {
    /// Prices exact usage at the authoritative external-effect start time.
    ///
    /// # Errors
    ///
    /// Returns [`DeepSeekProfileError::PricingUnavailable`] before midnight UTC
    /// on the pinned pricing revision date or for an invalid Unix timestamp.
    pub fn price_usage_at_micros(
        &self,
        effect_started_at: i64,
        usage: ProviderUsage,
    ) -> Result<u64, DeepSeekProfileError> {
        let effective_from = self
            .pricing_effective_from_unix_seconds()
            .ok_or(DeepSeekProfileError::PricingUnavailable)?;
        if effect_started_at < effective_from {
            return Err(DeepSeekProfileError::PricingUnavailable);
        }
        if DateTime::<Utc>::from_timestamp(effect_started_at, 0).is_none() {
            return Err(DeepSeekProfileError::PricingUnavailable);
        }
        self.price_usage_with_rates(usage)
    }

    fn pricing_effective_from_unix_seconds(&self) -> Option<i64> {
        let revision = self.raw.pricing.revision.as_str();
        let dated_revision = revision.strip_prefix("deepseek-flash-peak-")?;
        let (date, version) = dated_revision.split_once('/')?;
        if version != "1" {
            return None;
        }
        NaiveDate::parse_from_str(date, "%Y-%m-%d")
            .ok()?
            .and_hms_opt(0, 0, 0)
            .map(|datetime| datetime.and_utc().timestamp())
    }

    fn price_usage_with_rates(&self, usage: ProviderUsage) -> Result<u64, DeepSeekProfileError> {
        if usage.input_tokens() > self.raw.pricing.long_context_threshold_tokens {
            return Err(DeepSeekProfileError::UnsupportedPricingTier);
        }
        let uncached = usage
            .input_tokens()
            .checked_sub(usage.cached_input_tokens())
            .ok_or(DeepSeekProfileError::PricingOverflow)?;
        let unit = self.raw.pricing.unit_tokens;
        let input = prorated_micros(uncached, self.raw.pricing.input_micros, unit)?;
        let cached = prorated_micros(
            usage.cached_input_tokens(),
            self.raw.pricing.cached_input_micros,
            unit,
        )?;
        let output = prorated_micros(usage.output_tokens(), self.raw.pricing.output_micros, unit)?;
        input
            .checked_add(cached)
            .and_then(|subtotal| subtotal.checked_add(output))
            .ok_or(DeepSeekProfileError::PricingOverflow)
    }
}
