fn positive_u64(value: i64) -> rusqlite::Result<u64> {
    let value = u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)?;
    if value == 0 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(value)
}

fn nonnegative_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_bool(value: i64) -> rusqlite::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn decode_repository_state(value: i64) -> rusqlite::Result<ProviderRepositoryState> {
    match value {
        1 => Ok(ProviderRepositoryState::Dispatching),
        2 => Ok(ProviderRepositoryState::RejectedBeforeEffect),
        3 => Ok(ProviderRepositoryState::Streaming),
        4 => Ok(ProviderRepositoryState::TerminalPendingCommit),
        5 => Ok(ProviderRepositoryState::Settled),
        6 => Ok(ProviderRepositoryState::Uncertain),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(i64::MAX)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn fixed_bytes<const N: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
