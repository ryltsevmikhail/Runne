type UnknownReceiptOutputBinding = (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64);

struct UnknownReceiptCurrent {
    reason: i64,
    disposition: i64,
    usage_present: i64,
    input: Option<i64>,
    output_tokens: Option<i64>,
    cached: Option<i64>,
    reasoning: Option<i64>,
    output: Option<UnknownReceiptOutputBinding>,
    outbox_id: Option<Vec<u8>>,
    application_key: Option<String>,
    commitment: Vec<u8>,
    ack: Option<Vec<u8>>,
    terminal_sequence: i64,
}

fn decode_unknown_reason(
    value: i64,
) -> Result<ProviderUnknownAccountingReason, ProviderExecutionError> {
    match value {
        1 => Ok(ProviderUnknownAccountingReason::UsageUnavailable),
        2 => Ok(ProviderUnknownAccountingReason::PricingUnavailable),
        3 => Ok(ProviderUnknownAccountingReason::PricingInvalid),
        4 => Ok(ProviderUnknownAccountingReason::CurrencyMismatch),
        _ => Err(ProviderExecutionError::JournalCorrupt),
    }
}
