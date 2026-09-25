use chrono::{Datelike, Timelike, Utc};

#[derive(Clone, Copy)]
struct PriceRates {
    input: u64,
    cached_input: u64,
    output: u64,
}

impl PriceRates {
    const fn peak(pricing: &PricingProfile) -> Self {
        Self {
            input: pricing.peak_input_micros,
            cached_input: pricing.peak_cached_input_micros,
            output: pricing.peak_output_micros,
        }
    }

    const fn off_peak(pricing: &PricingProfile) -> Self {
        Self {
            input: pricing.off_peak_input_micros,
            cached_input: pricing.off_peak_cached_input_micros,
            output: pricing.off_peak_output_micros,
        }
    }
}

impl DeepSeekResponsesTextProfile {
    /// Prices exact usage at the authoritative external-effect start time.
    ///
    /// # Errors
    ///
    /// Returns [`DeepSeekProfileError::PricingUnavailable`] before the pinned
    /// pricing snapshot becomes effective or for an invalid Unix timestamp.
    pub fn price_usage_at_micros(
        &self,
        effect_started_at: i64,
        usage: ProviderUsage,
    ) -> Result<u64, DeepSeekProfileError> {
        if effect_started_at < self.raw.pricing.effective_from_unix_seconds {
            return Err(DeepSeekProfileError::PricingUnavailable);
        }
        let time = chrono::DateTime::<Utc>::from_timestamp(effect_started_at, 0)
            .ok_or(DeepSeekProfileError::PricingUnavailable)?;
        let weekday = u8::try_from(time.weekday().number_from_monday())
            .map_err(|_| DeepSeekProfileError::PricingUnavailable)?;
        let minute = u16::try_from(time.hour() * 60 + time.minute())
            .map_err(|_| DeepSeekProfileError::PricingUnavailable)?;
        let is_peak = self.raw.pricing.peak_iso_weekdays.contains(&weekday)
            && self
                .raw
                .pricing
                .peak_windows_utc
                .iter()
                .any(|window| (window[0]..window[1]).contains(&minute));
        let rates = if is_peak {
            PriceRates::peak(&self.raw.pricing)
        } else {
            PriceRates::off_peak(&self.raw.pricing)
        };
        self.price_usage_with_rates(usage, rates)
    }

    fn price_usage_with_rates(
        &self,
        usage: ProviderUsage,
        rates: PriceRates,
    ) -> Result<u64, DeepSeekProfileError> {
        if usage.input_tokens() > self.raw.pricing.long_context_threshold_tokens {
            return Err(DeepSeekProfileError::UnsupportedPricingTier);
        }
        let uncached = usage
            .input_tokens()
            .checked_sub(usage.cached_input_tokens())
            .ok_or(DeepSeekProfileError::PricingOverflow)?;
        let unit = self.raw.pricing.unit_tokens;
        let input = prorated_micros(uncached, rates.input, unit)?;
        let cached = prorated_micros(usage.cached_input_tokens(), rates.cached_input, unit)?;
        let output = prorated_micros(usage.output_tokens(), rates.output, unit)?;
        input
            .checked_add(cached)
            .and_then(|subtotal| subtotal.checked_add(output))
            .ok_or(DeepSeekProfileError::PricingOverflow)
    }
}
