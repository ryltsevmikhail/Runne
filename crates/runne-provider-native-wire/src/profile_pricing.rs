use super::core::NativeAccounting;
use runne_provider::{ProviderPricedUsage, ProviderTerminalPricingError, ProviderUsage};

pub(super) fn currency(accounting: NativeAccounting) -> &'static str {
    match accounting {
        NativeAccounting::Payg { .. } => "USD",
        NativeAccounting::SubscriptionQuotaExternallyMetered
        | NativeAccounting::TokenPlanQuotaExternallyMetered
        | NativeAccounting::ExternallyBilledUnpriced => "XXX",
    }
}

pub(super) fn price_usage(
    accounting: NativeAccounting,
    usage: ProviderUsage,
) -> Result<u64, ProviderTerminalPricingError> {
    let NativeAccounting::Payg {
        input_micros_per_million,
        output_micros_per_million,
        cached_input_micros_per_million,
        ..
    } = accounting
    else {
        return match accounting {
            NativeAccounting::SubscriptionQuotaExternallyMetered
            | NativeAccounting::TokenPlanQuotaExternallyMetered => Ok(0),
            NativeAccounting::ExternallyBilledUnpriced => {
                Err(ProviderTerminalPricingError::Unavailable)
            }
            NativeAccounting::Payg { .. } => unreachable!(),
        };
    };
    let uncached = usage
        .input_tokens()
        .checked_sub(usage.cached_input_tokens())
        .ok_or(ProviderTerminalPricingError::InvalidQuote)?;
    let input = prorated(uncached, input_micros_per_million)?;
    let cached = prorated(usage.cached_input_tokens(), cached_input_micros_per_million)?;
    let output = prorated(usage.output_tokens(), output_micros_per_million)?;
    input
        .checked_add(cached)
        .and_then(|total| total.checked_add(output))
        .ok_or(ProviderTerminalPricingError::InvalidQuote)
}

pub(super) fn price_terminal(
    accounting: NativeAccounting,
    usage: ProviderUsage,
) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
    ProviderPricedUsage::new(
        price_usage(accounting, usage)?,
        currency(accounting).to_owned(),
    )
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
