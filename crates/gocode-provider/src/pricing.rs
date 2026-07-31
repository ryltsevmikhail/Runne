use thiserror::Error;

use crate::ProviderUsage;

/// Runtime-trusted result of immutable pricing for exact provider usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPricedUsage {
    charge_micros: u64,
    currency: String,
}

impl ProviderPricedUsage {
    /// Constructs a bounded uppercase-currency price.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderTerminalPricingError::InvalidQuote`] for an
    /// unbounded charge or a non-canonical currency.
    pub fn new(charge_micros: u64, currency: String) -> Result<Self, ProviderTerminalPricingError> {
        if charge_micros > i64::MAX as u64
            || currency.len() != 3
            || !currency.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(ProviderTerminalPricingError::InvalidQuote);
        }
        Ok(Self {
            charge_micros,
            currency,
        })
    }

    /// Returns the exact fixed-point charge in currency micro-units.
    #[must_use]
    pub const fn charge_micros(&self) -> u64 {
        self.charge_micros
    }

    /// Returns the canonical three-letter currency.
    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }
}

/// Closed immutable-pricing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderTerminalPricingError {
    /// Pricing revision or profile is unavailable.
    #[error("provider pricing revision is unavailable")]
    Unavailable,
    /// Pricing returned malformed or unbounded values.
    #[error("provider pricing quote is invalid")]
    InvalidQuote,
}

/// Immutable pricing boundary pinned by trusted runtime composition.
pub trait ProviderTerminalPricing: Send + Sync {
    /// Prices exact authenticated usage under admitted profile and pricing
    /// revision digests.
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError>;
}
