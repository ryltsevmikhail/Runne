fn unknown_fixed_bytes<const N: usize>(value: Vec<u8>) -> Result<[u8; N], ProviderExecutionError> {
    fixed_bytes(value).map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn unknown_positive_u64(value: i64) -> Result<u64, ProviderExecutionError> {
    positive_u64(value).map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn unknown_nonnegative_u64(value: i64) -> Result<u64, ProviderExecutionError> {
    nonnegative_u64(value).map_err(|_| ProviderExecutionError::JournalCorrupt)
}
