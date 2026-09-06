use super::contract::PRICING_REVISION;

/// Maximum terminal input token count for the candidate budget.
pub const MAX_INPUT_TOKENS: u64 = 256;
/// Exact terminal output token count for the candidate budget.
pub const MAX_OUTPUT_TOKENS: u64 = 16;
/// Candidate reservation in micro-USD.
pub const RESERVATION_MICRO_USD: u64 = 135;

const UNIT_TOKENS: u64 = 1_000_000;
const INPUT_RATE_MICROS: u64 = 440_000;
const CACHED_INPUT_RATE_MICROS: u64 = 14_000;
const OUTPUT_RATE_MICROS: u64 = 1_320_000;
const RESERVATION_TENTHS: u64 = 1_350;
const CAP_TENTHS: u64 = 2_000;

/// Closed result of checked terminal accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingDisposition {
    /// Terminal usage was not supplied.
    MissingUsage,
    /// Usage was not terminal.
    NonterminalUsage,
    /// Cached input exceeds total input.
    CachedUnderflow,
    /// Checked integer arithmetic overflowed.
    Overflow,
    /// Checked integer subtraction underflowed.
    Underflow,
    /// Pricing identity differs from the compiled identity.
    PricingMismatch,
    /// A terminal settlement differs from the recorded settlement.
    SettlementMismatch,
    /// Terminal usage or cost exceeds the compiled budget cap.
    OverCap,
    /// One terminal settlement was reconciled.
    Reconciled,
    /// A conflicting or ambiguous state requires reconciliation.
    Uncertain,
}

/// Terminal usage counts supplied to pure accounting.
pub struct TerminalUsage {
    input: u64,
    output: u64,
    cached_input: u64,
}

impl TerminalUsage {
    /// Creates terminal usage counts.
    #[must_use]
    pub const fn new(input_tokens: u64, output_tokens: u64, cached_input_tokens: u64) -> Self {
        Self {
            input: input_tokens,
            output: output_tokens,
            cached_input: cached_input_tokens,
        }
    }
}

/// Reconciled accounting values with private terminal usage and settlement fields.
pub struct CanaryAccounting {
    usage: TerminalUsage,
    expected_cost_tenths: u64,
    pricing_revision: &'static str,
    reserved_tenths: u64,
    settled_tenths: u64,
    remaining_tenths: u64,
    settlement_count: u8,
    disposition: AccountingDisposition,
}

impl CanaryAccounting {
    /// Reconciles one terminal usage report against the compiled pricing identity.
    ///
    /// # Errors
    /// Returns a disposition when pricing, usage, or checked arithmetic is invalid.
    pub fn reconcile(
        usage: TerminalUsage,
        pricing_revision: &str,
    ) -> Result<Self, AccountingDisposition> {
        if pricing_revision != PRICING_REVISION {
            return Err(AccountingDisposition::PricingMismatch);
        }
        if usage.input > MAX_INPUT_TOKENS || usage.output > MAX_OUTPUT_TOKENS {
            return Err(AccountingDisposition::OverCap);
        }
        let expected_cost_tenths =
            Self::checked_expected_cost_tenths(usage.input, usage.output, usage.cached_input)?;
        if expected_cost_tenths > CAP_TENTHS {
            return Err(AccountingDisposition::OverCap);
        }
        Ok(Self {
            usage,
            expected_cost_tenths,
            pricing_revision: PRICING_REVISION,
            reserved_tenths: RESERVATION_TENTHS,
            settled_tenths: expected_cost_tenths,
            remaining_tenths: Self::checked_remaining_tenths(
                RESERVATION_TENTHS,
                expected_cost_tenths,
            )?,
            settlement_count: 1,
            disposition: AccountingDisposition::Reconciled,
        })
    }

    /// Computes expected cost in checked tenths of a micro-USD.
    ///
    /// # Errors
    /// Returns a disposition when cached input underflows or arithmetic overflows.
    pub fn checked_expected_cost_tenths(
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: u64,
    ) -> Result<u64, AccountingDisposition> {
        let uncached = input_tokens
            .checked_sub(cached_input_tokens)
            .ok_or(AccountingDisposition::CachedUnderflow)?;
        let uncached_cost = prorated_micros(uncached, INPUT_RATE_MICROS)?;
        let cached_cost = prorated_micros(cached_input_tokens, CACHED_INPUT_RATE_MICROS)?;
        let output_cost = prorated_micros(output_tokens, OUTPUT_RATE_MICROS)?;
        uncached_cost
            .checked_add(cached_cost)
            .and_then(|cost| cost.checked_add(output_cost))
            .and_then(|cost| cost.checked_mul(10))
            .ok_or(AccountingDisposition::Overflow)
    }

    /// Subtracts settled tenths from a supplied bound using checked arithmetic.
    ///
    /// # Errors
    /// Returns `AccountingDisposition::Underflow` when settlement exceeds the bound.
    pub fn checked_remaining_tenths(
        bound_tenths: u64,
        settled_tenths: u64,
    ) -> Result<u64, AccountingDisposition> {
        bound_tenths
            .checked_sub(settled_tenths)
            .ok_or(AccountingDisposition::Underflow)
    }

    /// Returns the expected cost in tenths of a micro-USD.
    #[must_use]
    pub const fn expected_cost_tenths(&self) -> u64 {
        self.expected_cost_tenths
    }
    /// Returns the expected cost in whole micro-USD.
    #[must_use]
    pub const fn expected_cost_micro_usd(&self) -> u64 {
        self.expected_cost_tenths / 10
    }
    /// Returns the terminal input token count.
    #[must_use]
    pub const fn input_tokens(&self) -> u64 {
        self.usage.input
    }
    /// Returns the terminal output token count.
    #[must_use]
    pub const fn output_tokens(&self) -> u64 {
        self.usage.output
    }
    /// Returns the terminal cached input token count.
    #[must_use]
    pub const fn cached_input_tokens(&self) -> u64 {
        self.usage.cached_input
    }
    /// Returns the compiled pricing revision.
    #[must_use]
    pub const fn pricing_revision(&self) -> &'static str {
        self.pricing_revision
    }
    /// Returns the compiled reservation in tenths of a micro-USD.
    #[must_use]
    pub const fn reserved_tenths(&self) -> u64 {
        self.reserved_tenths
    }
    /// Returns the settled cost in tenths of a micro-USD.
    #[must_use]
    pub const fn settled_tenths(&self) -> u64 {
        self.settled_tenths
    }
    /// Returns the remaining reservation in tenths of a micro-USD.
    #[must_use]
    pub const fn remaining_tenths(&self) -> u64 {
        self.remaining_tenths
    }
    /// Returns the terminal settlement count.
    #[must_use]
    pub const fn settlement_count(&self) -> u8 {
        self.settlement_count
    }
    /// Returns the closed accounting disposition.
    #[must_use]
    pub const fn disposition(&self) -> AccountingDisposition {
        self.disposition
    }
}

fn prorated_micros(tokens: u64, rate: u64) -> Result<u64, AccountingDisposition> {
    let numerator = tokens
        .checked_mul(rate)
        .ok_or(AccountingDisposition::Overflow)?;
    numerator
        .checked_add(UNIT_TOKENS - 1)
        .map(|rounded| rounded / UNIT_TOKENS)
        .ok_or(AccountingDisposition::Overflow)
}
