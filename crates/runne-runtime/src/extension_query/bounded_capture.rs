use super::MetadataQueryError;
pub(super) const MAX_INPUT_BYTES: usize = 1_048_576;
#[cfg(unix)]
pub(super) fn read_from_start(file: &std::fs::File) -> Result<Vec<u8>, MetadataQueryError> {
    use std::os::unix::fs::FileExt;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(MAX_INPUT_BYTES + 1)
        .map_err(|_| MetadataQueryError::InternalUnavailable)?;
    buffer.resize(MAX_INPUT_BYTES + 1, 0);
    let mut used = 0usize;
    let mut offset = 0u64;
    loop {
        match file.read_at(&mut buffer[used..], offset) {
            Ok(0) => {
                buffer.truncate(used);
                return Ok(buffer);
            }
            Ok(n) => {
                used = used
                    .checked_add(n)
                    .ok_or(MetadataQueryError::LimitExceeded)?;
                if used > MAX_INPUT_BYTES {
                    return Err(MetadataQueryError::LimitExceeded);
                }
                offset = offset
                    .checked_add(n as u64)
                    .ok_or(MetadataQueryError::LimitExceeded)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(MetadataQueryError::SourceUnavailable),
        }
    }
}
#[cfg(not(unix))]
pub(super) fn read_from_start(_file: &std::fs::File) -> Result<Vec<u8>, MetadataQueryError> {
    Err(MetadataQueryError::SourceUnavailable)
}
