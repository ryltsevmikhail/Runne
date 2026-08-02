fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn sha256_lower_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_database_generation(connection: &Connection) -> Result<u64, ReplayStoreError> {
    let generation: i64 = connection.query_row(
        "SELECT db_generation FROM meta WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    u64::try_from(generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)
}
