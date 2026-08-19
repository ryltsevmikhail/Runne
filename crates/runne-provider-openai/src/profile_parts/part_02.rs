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

    /// Returns the exact Standard processing tier.
    #[must_use]
    pub fn service_tier(&self) -> &str {
        &self.raw.request.service_tier
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

    /// Returns the Runne output-token ceiling for this profile.
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
        && profile.request.service_tier == OPENAI_SERVICE_TIER
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
